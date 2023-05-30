using Microsoft.AspNetCore.Http;
using Microsoft.AspNetCore.Mvc;
using Microsoft.AspNetCore.SignalR;
using System.Net;
using Ydb.Sdk.Auth;
using Ydb.Sdk;
using Ydb.Sdk.Table;
using Ydb.Sdk.Value;
using Ydb.Sdk.Yc;
using System.Security.Cryptography;
using Konscious.Security.Cryptography;
using System.Text;
using Microsoft.AspNetCore.DataProtection;
using System.IdentityModel.Tokens.Jwt;
using System;
using System.Security.Claims;
using Microsoft.AspNetCore.Authentication;
using Microsoft.AspNetCore.Authentication.JwtBearer;
using Microsoft.IdentityModel.Tokens;
using Microsoft.AspNetCore.Authentication.OAuth;
using Microsoft.AspNetCore.Authorization;
using Microsoft.IdentityModel.JsonWebTokens;
using System.IO;
using Grpc.Core;
using System.Security.Principal;
using System.Collections;
using System.Text.Json.Nodes;

namespace NAuthAPI.Controllers
{
    [Route("auth")]
    [ApiController]
    public class AuthController : ControllerBase
    {
        readonly AppContext _database;
        readonly string _pepper;
        readonly string _issuer;
        readonly string _audience;
        private bool IsDBInitialized => _database != null;
        public AuthController(IConfiguration webconfig, AppContext db)
        {
            _database = db;
            _pepper = webconfig["Pepper"] ?? "";
            _issuer = webconfig["Issuer"] ?? "";
            _audience = webconfig["Audience"] ?? "";
        }
        #region Endpoints Logic
        [HttpGet("db/status")]
        public ActionResult DatabaseStatus()
        {
            if (!IsDBInitialized)
                return Problem("Драйвер базы данных не инициализирован");
            else
                return Ok("Драйвер базы данных успешно запущен");
        }
        [HttpPost("signin")]
        public async Task<ActionResult> SignIn([FromForm] string username, [FromForm] string password, [FromHeader] string client_id, [FromHeader] string client_secret)
        {
            if (!IsDBInitialized)
                return Problem("Драйвер базы данных не инициализирован");
            var client = await GetClientAsync(client_id, client_secret);
            if (client == null)
                return BadRequest("Клиентское приложение не авторизовано");
            if (!client.IsImplementation) 
                return BadRequest("Клиент не имеет доверенной реализации потока системы");
            if (username == "" || password == "")
                return BadRequest("Нет данных для авторизации");

            try
            {
                Account? account = await _database.GetAccount(username);
                if (account == null)
                {
                    return Unauthorized("Неправильный логин или пароль");
                }
                else
                {
                    var guid = account.Identity.FindFirst(ClaimTypes.SerialNumber)?.Value ?? "";
                    var hash = await HashPassword(password, guid, Convert.FromBase64String(account.Salt));
                    if (IsHashValid(hash, account.Hash))
                    {
                        var key = await CreateSecurityKey();
                        var isKeyRegistered = await _database.CreateAuthKey(key.KeyId, _audience, guid);
                        if (isKeyRegistered)
                        {
                            var id = CreateIdToken(account.Identity.Claims, key);
                            var refresh = CreateRefreshToken(guid, key);
                            var result = new
                            {
                                id_token = id,
                                refresh_token = refresh
                            };
                            return Ok(result);
                        }
                        return NoContent();
                    }
                    else
                    {
                        return Unauthorized("Неправильный логин или пароль");
                    }
                }
            }
            catch (Exception ex)
            {
                return Problem(ex.Message);
            }
        }
        [HttpGet("account/exists")]
        public async Task<ActionResult> IsUserExists([FromQuery]string username, [FromHeader] string client_id, [FromHeader] string client_secret)
        {
            if (!IsDBInitialized)
                return Problem("Драйвер базы данных не инициализирован");
            var client = await GetClientAsync(client_id, client_secret);
            if (client == null)
                return BadRequest("Клиентское приложение не авторизовано");
            try
            {
                bool? exist = await _database.IsUsernameExists(username);
                if (exist == null)
                {
                    return NoContent();
                }
                else
                {
                    return Ok(exist);
                }
            }
            catch (Exception ex)
            {
                return Problem(ex.Message);
            }
        }
        [Authorize]
        [HttpGet("account")]
        public async Task<ActionResult> GetAccount([FromHeader] string client_id, [FromHeader] string client_secret)
        {
            if (!IsDBInitialized)
                return Problem("Драйвер базы данных не инициализирован");
            var client = await GetClientAsync(client_id, client_secret);
            if (client == null)
                return BadRequest("Клиентское приложение не авторизовано");
            try
            {
                Account? account = await _database.GetAccount(HttpContext.User.FindFirst(ClaimTypes.Upn)?.Value ?? "");
                if (account != null)
                {
                    return Ok(account.Identity.Claims);
                }
                else
                {
                    return NoContent();
                }
            }
            catch (Exception ex)
            {
                return Problem(ex.Message);
            }
        }
        [Authorize]
        [HttpPut("account/update")]
        public async Task<ActionResult> UpdateAccount([FromHeader] string client_id, [FromHeader] string client_secret)
        {
            if (!IsDBInitialized)
                return Problem("Драйвер базы данных не инициализирован");
            var client = await GetClientAsync(client_id, client_secret);
            if (client == null)
                return BadRequest("Клиентское приложение не авторизовано");
            if (!HttpContext.Request.HasFormContentType) 
                return BadRequest("Нет утверждений для изменения");
            var auth = await HttpContext.AuthenticateAsync();
            var scope = auth.Ticket?.Principal?.FindFirstValue("scope") ?? string.Empty;
            if (!scope.Contains("user")) return BadRequest("Полученный токен не предназначен для доступа к этому ресурсу");
            var form = await HttpContext.Request.ReadFormAsync();
            var user = HttpContext.User.FindFirst(ClaimTypes.SerialNumber)?.Value;
            if (user != null)
            {
                Dictionary<string, string> claims = new();
                foreach (var item in form) claims.Add(item.Key, item.Value.First() ?? "");
                
                var result = await _database.UpdateAccount(user, claims);
                if (result) 
                { 
                    return Ok();
                }
                else
                {
                    return BadRequest();
                }
            }
            else
            {
                return BadRequest("Авторизованный ключ не содержит имени пользователя");
            }
        }
        [HttpPost("signup")]
        public async Task<ActionResult> SignUp([FromHeader] string client_id, [FromHeader] string client_secret)
        {
            if (!IsDBInitialized) 
                return Problem("Драйвер базы данных не инициализирован");
            var client = await GetClientAsync(client_id, client_secret);
            if (client == null)
                return BadRequest("Клиентское приложение не авторизовано");
            if (client.IsImplementation) 
                return BadRequest("Клиент не имеет доверенной реализации потока системы");
            if (!HttpContext.Request.HasFormContentType)
                return BadRequest("Нет утверждений для изменения");
            var form = await HttpContext.Request.ReadFormAsync();
            if (form["username"] == "" || form["name"] == "" || form["password"] == "") 
                return BadRequest();

            string guid = Guid.NewGuid().ToString();
            var salt = CreateSalt();
            string hash = Convert.ToBase64String(await HashPassword(form["password"][0] ?? "", guid, salt));

            var claims = new List<Claim>()
            {
                new Claim(ClaimTypes.Upn, form["username"][0] ?? "", ClaimValueTypes.String, _issuer),
                new Claim(ClaimTypes.Surname, form["surname"][0] ?? "", ClaimValueTypes.String, _issuer),
                new Claim(ClaimTypes.Name, form["name"][0] ?? "", ClaimValueTypes.String, _issuer),
                new Claim("LastName", form["lastname"][0] ?? "", ClaimValueTypes.String, _issuer),
                new Claim(ClaimTypes.SerialNumber, guid, ClaimValueTypes.String, _issuer)
            };
            ClaimsIdentity identity = new(claims);
            Account account = new(identity, hash, Convert.ToBase64String(salt));

            var key = await CreateSecurityKey();
            var isKeyRegistered = await _database.CreateAuthKey(key.KeyId, _audience, guid);

            var isAccountCreated = await _database.CreateAccount(account);
            if (isAccountCreated)
            {
                if (isKeyRegistered)
                {
                    string id = CreateIdToken(account.Identity.Claims, key);
                    string refresh = CreateRefreshToken(guid, key);
                    var result = new
                    {
                        id_token = id,
                        refresh_token = refresh
                    };
                    return Ok(result);
                }
                return Accepted();
            }
            else
            {
                return Problem("Не удалось зарегистрировать пользователя");
            }
        }
        [Authorize]
        [HttpGet("token")]
        public async Task<ActionResult> Token([FromHeader] string client_id, [FromHeader] string client_secret)
        {
            if (!IsDBInitialized)
                return Problem("Драйвер базы данных не инициализирован");
            var client = await GetClientAsync(client_id, client_secret);
            if (client == null)
                return BadRequest("Клиентское приложение не авторизовано");

            var auth = await HttpContext.AuthenticateAsync();
            var scope = auth.Ticket?.Principal?.FindFirstValue("scope") ?? "";
            if (!scope.Contains("refresh"))
                return BadRequest("Полученный токен не предназначен для доступа к этому ресурсу");

            var token = auth.Ticket?.Properties.GetTokenValue("access_token") ?? "";

            var handler = new JwtSecurityTokenHandler();
            var id = handler.ReadJwtToken(token).Header.Kid;
            
            var isValid = await _database.IsKeyValid(id);
            if (isValid)
            {
                DeleteSecurityKey(id);
                await _database.DeleteAuthKey(id);
                var key = await CreateSecurityKey();
                string guid = auth.Principal?.FindFirstValue(ClaimTypes.SerialNumber) ?? "";
                await _database.CreateAuthKey(key.KeyId, _audience, guid);
                string access = CreateAccessToken(guid, key, "user");
                string refresh = CreateRefreshToken(guid, key);
                var result = new
                {
                    access_token = access,
                    refresh_token = refresh
                };
                return Ok(result);
            }
            else
            {
                return BadRequest("Токен не представлен в системе или уже деактивирован");
            }
        }
        [Authorize]
        [HttpGet("token/revoke")]
        public async Task<ActionResult> Revoke([FromHeader] string client_id, [FromHeader] string client_secret, [FromForm] string kid)
        {
            if (!IsDBInitialized)
                return Problem("Драйвер базы данных не инициализирован");
            var client = await GetClientAsync(client_id, client_secret);
            if (client == null)
                return BadRequest("Клиентское приложение не авторизовано");

            var auth = await HttpContext.AuthenticateAsync();
            var scope = auth.Ticket?.Principal?.FindFirstValue("scope") ?? "";
            if (!scope.Contains("user"))
                return BadRequest("Полученный токен не предназначен для доступа к этому ресурсу");

            try
            {
                DeleteSecurityKey(kid);
                await _database.DeleteAuthKey(kid);
                return Ok();
            }
            catch (Exception)
            {
                return Problem();
            }
        }
        [Authorize]
        [HttpGet("signout")]
        public async Task<ActionResult> SignOut([FromHeader] string client_id, [FromHeader] string client_secret)
        {
            if (!IsDBInitialized)
                return Problem("Драйвер базы данных не инициализирован");
            var client = await GetClientAsync(client_id, client_secret);
            if (client == null)
                return BadRequest("Клиентское приложение не авторизовано");

            var auth = await HttpContext.AuthenticateAsync();
            var scope = auth.Ticket?.Principal?.FindFirstValue("scope") ?? "";
            if (!scope.Contains("user"))
                return BadRequest("Полученный токен не предназначен для доступа к этому ресурсу");

            var user = HttpContext.User.FindFirst(ClaimTypes.SerialNumber)?.Value;
            if (user == null) return BadRequest("Нет идентификационной информации в токене");
            try
            {
                var keys = await _database.GetUserKeys(user);
                foreach (var key in keys) DeleteSecurityKey(key);
                await _database.DeleteUserAuthKeys(user);
                return Ok();
            }
            catch (Exception)
            {
                return Problem();
            }
        }
        [Authorize]
        [HttpGet("account/tokens")]
        public async Task<ActionResult> UserTokens([FromHeader] string client_id, [FromHeader] string client_secret)
        {
            if (!IsDBInitialized)
                return Problem("Драйвер базы данных не инициализирован");
            var client = await GetClientAsync(client_id, client_secret);
            if (client == null)
                return BadRequest("Клиентское приложение не авторизовано");
            try
            {
                string user = HttpContext.User.FindFirstValue(ClaimTypes.SerialNumber) ?? "";
                var keys = await _database.GetUserKeys(user);
                return Ok(keys);
            }
            catch (Exception)
            {
                return Problem();
            }
        }
        #endregion
        #region Logic
        private async Task<Client?> GetClientAsync(string client_id, string client_secret)
        {
            if (client_id == "" || client_secret == "") 
                return null;
            if (!IsDBInitialized) 
                return null;

            var client = await _database.GetClient(client_id);
            if (client == null) 
                return null;

            if (client.Secret == client_secret && client.IsValid) 
                return client;
            else
                return null;
        }
        private static byte[] CreateSalt()
        {
            return CreateRandBytes(16);
        }
        private static byte[] CreateRandBytes(int bytes)
        {
            var buffer = new byte[bytes];
            var rng = RandomNumberGenerator.Create();
            rng.GetBytes(buffer);
            return buffer;
        }
        private async Task<byte[]> HashPassword(string password, string guid, byte[] salt)//OWASP
        {
            byte[] _password = Encoding.UTF8.GetBytes(password);
            var argon2 = new Argon2id(_password)
            {
                DegreeOfParallelism = 1,
                MemorySize = 19456,
                Iterations = 2,
                Salt = salt,
                AssociatedData = Encoding.UTF8.GetBytes(guid),
                KnownSecret = Encoding.UTF8.GetBytes(_pepper)
            };

            var hash = await argon2.GetBytesAsync(32);
            
            argon2.Dispose();
            argon2.Reset();
            argon2 = null;
            GC.Collect();

            return hash;
        }
        private static bool IsHashValid(byte[] hash, string db_hash) => hash.SequenceEqual(Convert.FromBase64String(db_hash));
        private static async Task<SymmetricSecurityKey> CreateSecurityKey()
        {
            var bytes = CreateRandBytes(32);
            var key = new SymmetricSecurityKey(bytes)
            {
                KeyId = Guid.NewGuid().ToString()
            };
            await System.IO.File.WriteAllTextAsync($"keys/{key.KeyId}.key", Convert.ToBase64String(key.Key));
            return key;
        }
        private static void DeleteSecurityKey(string keyId)
        {
            System.IO.File.Delete($"keys/{keyId}.key");
        }
        private string CreateIdToken(IEnumerable<Claim> claims, SymmetricSecurityKey key)
        {
            claims.Append(new Claim("scope", "id", ClaimValueTypes.String, _issuer));
            var token = CreateToken(claims, key, TimeSpan.FromHours(10));
            return token;
        }
        private string CreateRefreshToken(string guid, SymmetricSecurityKey key)
        {
            var claims = new List<Claim>() { 
                new Claim(ClaimTypes.SerialNumber, guid, ClaimValueTypes.String, _issuer),
                new Claim("scope", "refresh", ClaimValueTypes.String, _issuer)
            };
            var token = CreateToken(claims, key, TimeSpan.FromDays(14));
            return token;
        }
        private string CreateAccessToken(string guid, SymmetricSecurityKey key, string scope)
        {
            var claims = new List<Claim>() {
                new Claim(ClaimTypes.SerialNumber, guid, ClaimValueTypes.String, _issuer),
                new Claim("scope", scope, ClaimValueTypes.String, _issuer)
            };
            var token = CreateToken(claims, key, TimeSpan.FromHours(1));
            return token;
        }
        private string CreateToken(IEnumerable<Claim> claims, SymmetricSecurityKey key, TimeSpan lifetime)
        {
            var now = DateTime.UtcNow;
            var jwt = new JwtSecurityToken(
                _issuer,
                _audience,
                claims,
                now,
                now.Add(lifetime),
                new SigningCredentials(key, SecurityAlgorithms.HmacSha256));
            var token = new JwtSecurityTokenHandler().WriteToken(jwt);
            return token;
        }
        #endregion
    }
}
