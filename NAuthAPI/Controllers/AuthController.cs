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
    [Authorize]
    [Route("auth")]
    [ApiController]
    public class AuthController : ControllerBase
    {
        readonly AppContext _database;
        readonly KeyLakeService _lakeService;
        readonly string _pepper;
        readonly string _issuer;
        readonly string _audience;
        private bool IsDBInitialized => _database != null;
        public AuthController(IConfiguration webconfig, AppContext db, KeyLakeService lakeService)
        {
            _database = db;
            _lakeService = lakeService;
            _pepper = webconfig["Pepper"] ?? "";
            _issuer = webconfig["Issuer"] ?? "";
            _audience = webconfig["Audience"] ?? "";
        }

        #region Endpoints Logic

        [AllowAnonymous]
        [HttpPost("signin")]
        public async Task<ActionResult> SignIn([FromForm] string username, [FromForm] string password, [FromHeader] string client, [FromHeader] string secret)
        {
            if (!IsDBInitialized)
            {
                return Problem("Драйвер базы данных не инициализирован");
            }
                
            Client? _client = await Client.GetClientAsync(_database, client, secret);
            if (_client != null)
            {
                if (_client.IsImplementation)
                {
                    return BadRequest("Клиент не имеет доверенной реализации потока системы");
                }
            }
            else
            {
                return BadRequest("Клиентское приложение не авторизовано");
            }

            if (string.IsNullOrEmpty(username) || string.IsNullOrEmpty(password))
            {
                return BadRequest("Невозможно выполнить вход с пустыми идентификатором и паролем");
            }

            Account? account = await _database.GetAccountByUsername(username);
            if (account != null)
            {
                if (account.IsBlocked)
                {
                    return Forbid();
                }
                if (account.Attempts > 2)
                {
                    return Forbid();
                }
                string id = account.Identity.FindFirst(ClaimTypes.SerialNumber)?.Value ?? "";
                byte[] hash = await HashPassword(password, id, Convert.FromBase64String(account.Salt));
                if (IsHashValid(hash, account.Hash))
                {
                    await _database.NullAttempt(id);
                    string keyId = Guid.NewGuid().ToString();
                    var payload = await _lakeService.CreateKey(keyId);
                    var key = new SymmetricSecurityKey(Convert.FromBase64String(payload)) { KeyId = keyId };
                    if (await _database.CreateAuthKey(keyId, _audience, id))
                    {
                        var result = new
                        {
                            id_token = CreateIdToken(account.Identity.Claims, key),
                            refresh_token = CreateRefreshToken(id, key)
                        };
                        return Ok(result);
                    }
                    return NoContent();
                }
                else
                {
                    await _database.AddAttempt(id);
                    return Unauthorized("Неправильный логин или пароль");
                }
            }
            else
            {
                return Unauthorized("Учётная запись не существует");
            }
        }
        [AllowAnonymous]
        [HttpPost("signup")]
        public async Task<ActionResult> SignUp([FromHeader] string client, [FromHeader] string secret)
        {
            if (!IsDBInitialized)
            {
                return Problem("Драйвер базы данных не инициализирован");
            }

            Client? _client = await Client.GetClientAsync(_database, client, secret);
            if (_client != null)
            {
                if (_client.IsImplementation)
                {
                    return BadRequest("Клиент не имеет доверенной реализации потока системы");
                }
            }
            else
            {
                return BadRequest("Клиентское приложение не авторизовано");
            }

            IFormCollection form;
            if (HttpContext.Request.HasFormContentType)
            {
                form = await HttpContext.Request.ReadFormAsync();
            }
            else
            {
                return BadRequest("Запрос не содержит регистрационной формы");
            }

            string username;
            string password;
            if (form.ContainsKey("username") && form.ContainsKey("password"))
            {
                username = form["username"].First() ?? "";
                password = form["password"].First() ?? "";
                if (string.IsNullOrEmpty(username) || string.IsNullOrEmpty(password))
                {
                    return BadRequest("Нельзя создать учётную запись с пустыми идентификатором и паролем");
                }
            }
            else
            {
                return BadRequest("Невозможно создать учётную запись без идентификатора и пароля");
            }
            
            string id = Guid.NewGuid().ToString();
            byte[] salt = CreateSalt();
            byte[] hash = await HashPassword(password, id, salt);

            string stringScopes = "username surname name lastname email gender";
            string integerScopes = "phone";

            List<Claim> claims = new()
            {
                new Claim(ClaimTypes.SerialNumber, id, ClaimValueTypes.String, _issuer)
            };
            foreach(var formKey in form.Keys)
            {
                if (string.IsNullOrEmpty(formKey)) continue;
                string claimTypeValue;
                if (stringScopes.Contains(formKey))
                {
                    claimTypeValue = ClaimValueTypes.String;
                }
                else if (integerScopes.Contains(formKey))
                {
                    claimTypeValue = ClaimValueTypes.UInteger64;
                }
                else
                {
                    continue;
                }
                string claimType = formKey switch
                {
                    "username" => ClaimTypes.Upn,
                    "surname" => ClaimTypes.Surname,
                    "name" => ClaimTypes.Name,
                    "email" => ClaimTypes.Email,
                    "gender" => ClaimTypes.Gender,
                    "phone" => ClaimTypes.MobilePhone,
                    _ => formKey
                };
                Claim claim = new Claim(claimType, form[formKey].First() ?? "", claimTypeValue, _issuer);
                claims.Add(claim);
            }
            ClaimsIdentity identity = new(claims);
            Account account = new(identity, Convert.ToBase64String(hash), Convert.ToBase64String(salt), false, 0);

            string keyId = Guid.NewGuid().ToString();
            string payload = await _lakeService.CreateKey(keyId);
            var key = new SymmetricSecurityKey(Convert.FromBase64String(payload)) { KeyId = keyId };

            if (await _database.CreateAccount(account))
            {
                await _database.CreateAccept(id, "NAuth", "user");
                await _database.CreateAccept(id, "NAuth", "sign");
                if (await _database.CreateAuthKey(key.KeyId, _audience, id))
                {
                    var result = new
                    {
                        id_token = CreateIdToken(account.Identity.Claims, key),
                        refresh_token = CreateRefreshToken(id, key)
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
        [HttpGet("token")]
        public async Task<ActionResult> CreateToken([FromHeader] string client, [FromHeader] string secret)
        {
            if (!IsDBInitialized)
            {
                return Problem("Драйвер базы данных не инициализирован");
            }
                
            Client? _client = await Client.GetClientAsync(_database, client, secret);
            if (_client == null)
            {
                return Unauthorized("Клиентское приложение не авторизовано");
            }
            
            AuthenticateResult authResult = await HttpContext.AuthenticateAsync();
            string scope = authResult.Ticket?.Principal?.FindFirstValue("scope") ?? "";
            string userId = authResult.Principal?.FindFirstValue(ClaimTypes.SerialNumber) ?? "";
            if (!scope.Contains("refresh"))
            {
                return BadRequest("Полученный токен не предназначен для доступа к этому ресурсу");
            }

            var handler = new JwtSecurityTokenHandler();
            string token = authResult.Ticket?.Properties.GetTokens().First().Value ?? "";
            string id = handler.ReadJwtToken(token).Header.Kid;
            
            if (await _database.IsKeyValid(id))
            {
                if (!await _lakeService.DeleteKey(id))
                {
                    return Problem("Озеро ключей не удалило ключ");
                }
                if (!await _database.DeleteAuthKey(id)) 
                { 
                    return Problem("Текущий идентификатор ключа подписи не удалён из базы данных"); 
                }

                string keyId = Guid.NewGuid().ToString();
                string payload = await _lakeService.CreateKey(keyId);
                var key = new SymmetricSecurityKey(Convert.FromBase64String(payload)) { KeyId = keyId };
                if(!await _database.CreateAuthKey(key.KeyId, _audience, userId))
                {
                    return Problem("Новый ключ подписи не создан в базе данных");
                }

                List<string> acceptedScopes = await _database.GetAccepts(userId, client);
                StringBuilder validScopes = new StringBuilder();
                validScopes.AppendJoin(" ", _client.Scopes.Intersect(acceptedScopes));

                string access = CreateAccessToken(userId, key, validScopes.ToString());
                string refresh = CreateRefreshToken(userId, key);
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
        [HttpDelete("token")]
        public async Task<ActionResult> RevokeToken([FromHeader] string client_id, [FromHeader] string client_secret)
        {
            if (!IsDBInitialized)
                return Problem("Драйвер базы данных не инициализирован");
            var client = await Client.GetClientAsync(_database, client_id, client_secret);
            if (client == null)
                return BadRequest("Клиентское приложение не авторизовано");

            var auth = await HttpContext.AuthenticateAsync();
            var scope = auth.Ticket?.Principal?.FindFirstValue("scope") ?? "";
            if (!scope.Contains("refresh"))
            {
                return BadRequest("Полученный токен не предназначен для доступа к этому ресурсу");
            }
            var token = auth.Properties?.GetTokens().First().Value;
            var handler = new JwtSecurityTokenHandler();
            var kid = handler.ReadJwtToken(token).Header.Kid;
            if (!await _lakeService.DeleteKey(kid))
            {
                return Problem("Ключ подписи не удалён из озера ключей");
            }
            if (!await _database.DeleteAuthKey(kid))
            {
                return Problem("Идентификатор ключа подписи не удалён из базы данных");
            }
            return Ok();
        }
        [HttpPost("accept")]
        public async Task<ActionResult> AcceptData([FromQuery] string issuer, [FromQuery] string requiredScope, [FromHeader] string client, [FromHeader] string secret)
        {
            if (!IsDBInitialized)
            {
                return Problem("Драйвер базы данных не инициализирован");
            }
            Client? _client = await Client.GetClientAsync(_database, client, secret);
            if (_client != null)
            {
                if (_client.IsImplementation)
                {
                    return BadRequest("Клиент не имеет доверенной реализации потока системы");
                }
            }
            else
            {
                return BadRequest("Клиентское приложение не авторизовано");
            }
            AuthenticateResult authResult = await HttpContext.AuthenticateAsync();
            string tokenScope = authResult.Ticket?.Principal?.FindFirstValue("scope") ?? "";
            if (!tokenScope.Contains("refresh"))
            {
                return BadRequest("Полученный токен не предназначен для доступа к этому ресурсу");
            }
            string user_id = HttpContext.User.FindFirst(ClaimTypes.SerialNumber)?.Value ?? "";
            if (string.IsNullOrEmpty(user_id))
            {
                return BadRequest("Токен не содержит идентификационную информацию");
            }
            try
            {
                if (await _database.CreateAccept(user_id, issuer, requiredScope))
                {
                    return Ok();
                }
                else
                {
                    return Problem();
                }
            }
            catch (Exception)
            {
                return Problem();
            }
        }
        [HttpPost("revoke")]
        public async Task<ActionResult> RevokeData([FromQuery] string issuer, [FromHeader] string client, [FromHeader] string secret)
        {
            if (!IsDBInitialized)
            {
                return Problem("Драйвер базы данных не инициализирован");
            }
            Client? _client = await Client.GetClientAsync(_database, client, secret);
            if (_client != null)
            {
                if (_client.IsImplementation)
                {
                    return BadRequest("Клиент не имеет доверенной реализации потока системы");
                }
            }
            else
            {
                return BadRequest("Клиентское приложение не авторизовано");
            }
            AuthenticateResult authResult = await HttpContext.AuthenticateAsync();
            string tokenScope = authResult.Ticket?.Principal?.FindFirstValue("scope") ?? "";
            if (!tokenScope.Contains("refresh"))
            {
                return BadRequest("Полученный токен не предназначен для доступа к этому ресурсу");
            }
            string user_id = HttpContext.User.FindFirst(ClaimTypes.SerialNumber)?.Value ?? "";
            if (string.IsNullOrEmpty(user_id))
            {
                return BadRequest("Токен не содержит идентификационную информацию");
            }
            try
            {
                var result = await _database.DeleteAccept(user_id, issuer);
                if (result)
                {
                    return Ok();
                }
                else
                {
                    return Problem();
                }
            }
            catch (Exception)
            {
                return Problem();
            }
        }
        [HttpGet("signout")]
        public async Task<ActionResult> SignOut([FromHeader] string client, [FromHeader] string secret)
        {
            if (!IsDBInitialized)
            {
                return Problem("Драйвер базы данных не инициализирован");
            }
                
            Client? _client = await Client.GetClientAsync(_database, client, secret);
            if (_client != null)
            {
                if (_client.IsImplementation)
                {
                    return BadRequest("Клиент не имеет доверенной реализации потока системы");
                }
            }
            else
            {
                return BadRequest("Клиентское приложение не авторизовано");
            }

            var auth = await HttpContext.AuthenticateAsync();
            var scope = auth.Ticket?.Principal?.FindFirstValue("scope") ?? "";
            if (!scope.Contains("refresh"))
            {
                return BadRequest("Полученный токен не предназначен для доступа к этому ресурсу");
            }
                
            var id = HttpContext.User.FindFirst(ClaimTypes.SerialNumber)?.Value;
            if (string.IsNullOrEmpty(id)) 
            {
                return BadRequest("Нет идентификационной информации в токене");
            } 

            var keys = await _database.GetUserKeys(id);
            foreach (var key in keys)
                await _lakeService.DeleteKey(key);
            if (await _database.DeleteUserAuthKeys(id))
            {
                return Ok();
            }
            else
            {
                return Problem("Не удалось выполнить выход");
            }
        }
        [HttpPost("reset")]
        public async Task<ActionResult> ResetPassword([FromForm] string password, [FromHeader] string client, [FromHeader] string secret)
        {
            if (!IsDBInitialized)
            {
                return Problem("Драйвер базы данных не инициализирован");
            }

            Client? _client = await Client.GetClientAsync(_database, client, secret);
            if (_client != null)
            {
                if (_client.IsImplementation)
                {
                    return BadRequest("Клиент не имеет доверенной реализации потока системы");
                }
            }
            else
            {
                return BadRequest("Клиентское приложение не авторизовано");
            }

            var auth = await HttpContext.AuthenticateAsync();
            var scope = auth.Ticket?.Principal?.FindFirstValue("scope") ?? "";
            if (!scope.Contains("refresh"))
            {
                return BadRequest("Полученный токен не предназначен для доступа к этому ресурсу");
            }

            string id = HttpContext.User.FindFirst(ClaimTypes.SerialNumber)?.Value ?? string.Empty;
            if (string.IsNullOrEmpty(id))
            {
                return BadRequest("Нет идентификационной информации в токене");
            }

            byte[] salt = CreateSalt();
            byte[] hash = await HashPassword(password, id, salt);
            if (await _database.SetPasswordHash(id, Convert.ToBase64String(hash)))
            {
                return Ok();
            }
            else
            {
                return Problem("Не удалось сбросить пароль");
            }
        }
        
        #endregion

        #region Private Logic

        private static byte[] CreateSalt()
        {
            return CreateRandBytes(32);
        }
        private static byte[] CreateRandBytes(int bytes)
        {
            var buffer = new byte[bytes];
            var generator = RandomNumberGenerator.Create();
            generator.GetBytes(buffer);
            return buffer;
        }
        private async Task<byte[]> HashPassword(string password, string guid, byte[] salt)
        {
            byte[] _password = Encoding.UTF8.GetBytes(password);
            using (var argon2 = new Argon2id(_password)//Recommended parameters by OWASP
            {
                DegreeOfParallelism = 1,
                MemorySize = 19456,
                Iterations = 2,
                Salt = salt,
                AssociatedData = Encoding.UTF8.GetBytes(guid),
                KnownSecret = Encoding.UTF8.GetBytes(_pepper)
            })
            {
                var hash = await argon2.GetBytesAsync(32);

                argon2.Dispose();
                argon2.Reset();
                //argon2 = null;//Releases memmory (without leak)
                GC.Collect();

                return hash;
            }
        }
        private static bool IsHashValid(byte[] hash, string db_hash) => hash.SequenceEqual(Convert.FromBase64String(db_hash));
        private string CreateIdToken(IEnumerable<Claim> claims, SymmetricSecurityKey key)
        {
            _ = claims.Append(new Claim("scope", "id", ClaimValueTypes.String, _issuer));
            var token = CreateToken(claims, key, TimeSpan.FromHours(10));
            return token;
        }
        private string CreateRefreshToken(string guid, SymmetricSecurityKey key)
        {
            var claims = new List<Claim>() { 
                new Claim(ClaimTypes.SerialNumber, guid, ClaimValueTypes.String, _issuer),
                new Claim("scope", "refresh accept", ClaimValueTypes.String, _issuer)
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
