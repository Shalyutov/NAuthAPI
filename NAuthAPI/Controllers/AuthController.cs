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
    [Route("auth/api")]
    [ApiController]
    public class AuthController : ControllerBase
    {
        readonly YdbContext _database;
        readonly string _pepper;
        public AuthController(IConfiguration webconfig, YdbContext db)
        {
            _database = db;
            _pepper = webconfig["Pepper"] ?? "";
        }
        private bool IsDBInitialized()
        {
            if (_database != null)
            {
                return true;
            }
            else 
            {
                return false;
            }
        }
        [HttpGet("db/status")]
        public ActionResult DatabaseStatus()
        {
            if (!IsDBInitialized())
                return Problem("Драйвер базы данных не инициализирован");
            else
                return Ok("Драйвер базы данных успешно запущен.");
        }
        [HttpPost("signin")]
        public async Task<ActionResult> SignIn([FromForm] string username, [FromForm] string password, [FromForm] string client_id, [FromForm] string client_secret)//add client validation
        {
            if (!IsDBInitialized())
                return Problem("Драйвер базы данных не инициализирован");
            if (client_id != "NAUTH" || client_secret != "758694321")
                return Forbid("Неверные данные клиентского приложения");
            if (username == "" || password == "")
                return Unauthorized("Нет данных для авторизации");

            try
            {
                Account? account = await _database.GetAccount(username);
                if (account == null)
                {
                    return Unauthorized("Неправильный логин или пароль");
                }
                else
                {
                    var guid = account.Identity.FindFirst(ClaimTypes.SerialNumber)?.Value;
                    var hash = await HashPassword(password, guid ?? "", Convert.FromBase64String(account.Salt));
                    if (IsHashValid(hash, account.Hash))
                    {
                        var key = await CreateSecurityKey();
                        var isKeyRegistered = await _database.CreateAuthKey(key.KeyId, AuthProperties.AUDIENCE, guid ?? "");
                        if (isKeyRegistered)
                        {
                            var id = CreateIdToken(account.Identity.Claims, key);
                            var refresh = CreateRefreshToken(guid ?? "", key);
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
        public async Task<ActionResult> IsUserExists([FromQuery]string username, [FromForm] string client_id, [FromForm] string client_secret)
        {
            if (!IsDBInitialized())
                return Problem("Драйвер базы данных не инициализирован");
            if (client_id != "NAUTH" || client_secret != "758694321")
                return Forbid("Неверные данные клиентского приложения");
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
        public async Task<ActionResult> GetAccount([FromForm] string client_id, [FromForm] string client_secret)
        {
            if (!IsDBInitialized())
                return Problem("Драйвер базы данных не инициализирован");
            if (client_id != "NAUTH" || client_secret != "758694321")
                return Forbid("Неверные данные клиентского приложения");
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
        [HttpPost("signup")]
        public async Task<ActionResult> SignUp([FromForm] string username, [FromForm] string surname, [FromForm] string name, [FromForm] string lastname, [FromForm] string password, [FromForm] string client_id, [FromForm] string client_secret)
        {
            if (username == "" || name == "" || password == "") 
                return BadRequest();
            if (client_id != "NAUTH" || client_secret != "758694321")
                return Forbid("Неверные данные клиентского приложения");
            if (!IsDBInitialized()) 
                return Problem("Драйвер базы данных не инициализирован");

            string guid = Guid.NewGuid().ToString();
            var salt = CreateSalt();
            string hash = Convert.ToBase64String(await HashPassword(password, guid, salt));

            var claims = new List<Claim>()
            {
                new Claim(ClaimTypes.Upn, username, ClaimValueTypes.String, AuthProperties.ISSUER),
                new Claim(ClaimTypes.Surname, surname, ClaimValueTypes.String, AuthProperties.ISSUER),
                new Claim(ClaimTypes.Name, name, ClaimValueTypes.String, AuthProperties.ISSUER),
                new Claim("LastName", name, ClaimValueTypes.String, AuthProperties.ISSUER),
                new Claim(ClaimTypes.SerialNumber, guid, ClaimValueTypes.String, AuthProperties.ISSUER)
            };
            ClaimsIdentity identity = new(claims);
            Account account = new(identity, hash, Convert.ToBase64String(salt));

            var key = await CreateSecurityKey();
            var isKeyRegistered = await _database.CreateAuthKey(key.KeyId, AuthProperties.AUDIENCE, guid);

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
        public async Task<ActionResult> Token([FromForm] string client_id, [FromForm] string client_secret)
        {
            if (client_id != "NAUTH" || client_secret != "758694321")
                return Forbid("Неверные данные клиентского приложения");
            if (!IsDBInitialized())
                return Problem("Драйвер базы данных не инициализирован");
            var auth = await HttpContext.AuthenticateAsync();
            var token = await HttpContext.GetTokenAsync(JwtBearerDefaults.AuthenticationScheme, "access_token");
            var handler = new JwtSecurityTokenHandler();
            var id = handler.ReadJwtToken(token).Header.Kid;
            var token_name = auth.Principal?.FindFirstValue("token") ?? "";
            if (token_name == "refresh")
            {
                var isValid = await _database.IsKeyValid(id);
                if (isValid)
                {
                    DeleteSecurityKey(id);
                    await _database.DeleteAuthKey(id);
                    var key = await CreateSecurityKey();
                    string guid = auth.Principal?.FindFirstValue(ClaimTypes.SerialNumber) ?? "";
                    await _database.CreateAuthKey(key.KeyId, AuthProperties.AUDIENCE, guid);
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
                    return Unauthorized();
                }
            }
            else
            {
                return Unauthorized();
            }
        }
        [HttpGet("token/revoke")]
        public async Task<ActionResult> Revoke([FromForm] string client_id, [FromForm] string client_secret, [FromForm] string kid)
        {
            if (client_id != "NAUTH" || client_secret != "758694321")
                return Forbid("Неверные данные клиентского приложения");
            if (!IsDBInitialized())
                return Problem("Драйвер базы данных не инициализирован");
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
        [HttpGet("signout")]
        public async Task<ActionResult> SignOut([FromForm] string client_id, [FromForm] string client_secret, [FromForm] string user)
        {
            if (client_id != "NAUTH" || client_secret != "758694321")
                return Forbid("Неверные данные клиентского приложения");
            if (!IsDBInitialized())
                return Problem("Драйвер базы данных не инициализирован");
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
        public async Task<ActionResult> UserTokens([FromForm] string client_id, [FromForm] string client_secret)
        {
            if (client_id != "NAUTH" || client_secret != "758694321")
                return Forbid("Неверные данные клиентского приложения");
            if (!IsDBInitialized())
                return Problem("Драйвер базы данных не инициализирован");
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
        private static async Task<SymmetricSecurityKey> GetSecurityKey(string keyId)
        {
            var keystr = await System.IO.File.ReadAllTextAsync($"keys/{keyId}.key");
            var key = new SymmetricSecurityKey(Convert.FromBase64String(keystr))
            {
                KeyId = keyId
            };
            return key;
        }
        private void DeleteSecurityKey(string keyId)
        {
            System.IO.File.Delete($"keys/{keyId}.key");
        }
        private string CreateIdToken(IEnumerable<Claim> claims, SymmetricSecurityKey key)
        {
            claims.Append(new Claim("token", "id", ClaimValueTypes.String, AuthProperties.ISSUER));
            var token = CreateToken(claims, key, TimeSpan.FromHours(10));
            return token;
        }
        private string CreateRefreshToken(string guid, SymmetricSecurityKey key)
        {
            var claims = new List<Claim>() { 
                new Claim(ClaimTypes.SerialNumber, guid, ClaimValueTypes.String, AuthProperties.ISSUER),
                new Claim("token", "refresh", ClaimValueTypes.String, AuthProperties.ISSUER)
            };
            var token = CreateToken(claims, key, TimeSpan.FromDays(14));
            return token;
        }
        private string CreateAccessToken(string guid, SymmetricSecurityKey key, string scope)
        {
            var claims = new List<Claim>() {
                new Claim(ClaimTypes.SerialNumber, guid, ClaimValueTypes.String, AuthProperties.ISSUER),
                new Claim("scope", scope, ClaimValueTypes.String, AuthProperties.ISSUER),
                new Claim("token", "access", ClaimValueTypes.String, AuthProperties.ISSUER)
            };
            var token = CreateToken(claims, key, TimeSpan.FromHours(1));
            return token;
        }
        private static string CreateToken(IEnumerable<Claim> claims, SymmetricSecurityKey key, TimeSpan lifetime)
        {
            var now = DateTime.UtcNow;
            var jwt = new JwtSecurityToken(
                AuthProperties.ISSUER,
                AuthProperties.AUDIENCE,
                claims,
                now,
                now.Add(lifetime),
                new SigningCredentials(key, SecurityAlgorithms.HmacSha256));
            var token = new JwtSecurityTokenHandler().WriteToken(jwt);
            return token;
        }
    }
    public class AuthProperties
    {
        public static string ISSUER = "NAuth API";
        public static string AUDIENCE = "NAuth App";
    }
}
