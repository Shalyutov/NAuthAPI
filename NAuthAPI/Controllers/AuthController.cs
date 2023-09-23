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
using static Ydb.Monitoring.SelfCheck.Types;
using Org.BouncyCastle.Asn1.Ocsp;
using static System.Formats.Asn1.AsnWriter;

namespace NAuthAPI.Controllers
{
    [Authorize]
    [Route("auth")]
    [ApiController]
    public class AuthController : ControllerBase
    {
        readonly AppContext _database;
        readonly IKVEngine _kvService;
        readonly string _pepper;
        readonly string _issuer;
        readonly string _audience;
        
        public AuthController(AuthNames names, AppContext db, IKVEngine kvService)
        {
            _database = db;
            _kvService = kvService;
            _pepper = kvService.GetPepper();
            _issuer = names.Issuer;
            _audience = names.Audience;
        }

        #region Endpoints Logic

        [TrustClient]
        [AllowAnonymous]
        [HttpPost("signin")]
        public async Task<ActionResult> SignIn([FromForm] string username, [FromForm] string password)
        {
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
                if (string.IsNullOrEmpty(account.Hash))
                {
                    return Forbid();
                }
                if (IsHashValid(hash, account.Hash))
                {
                    await _database.NullAttempt(id);
                    string keyId = Guid.NewGuid().ToString();
                    var payload = _kvService.CreateKey(keyId);
                    var key = new SymmetricSecurityKey(Convert.FromBase64String(payload)) { KeyId = keyId };
                    string client = ((Client?)HttpContext.Items["client"])!.Name ?? "";
                    if (await _database.CreateAuthKey(keyId, _audience, id))
                    {
                        var result = new
                        {
                            id_token = CreateIdToken(account.Identity.Claims, key, client),
                            refresh_token = CreateRefreshToken(id, key, client)
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
        [TrustClient]
        [AllowAnonymous]
        [HttpPost("signup")]
        public async Task<ActionResult> SignUp()
        {
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
                Claim claim = new(claimType, form[formKey].First() ?? "", claimTypeValue, _issuer);
                claims.Add(claim);
            }
            ClaimsIdentity identity = new(claims);
            Account account = new(identity, Convert.ToBase64String(hash), Convert.ToBase64String(salt), false, 0);

            string keyId = Guid.NewGuid().ToString();
            string payload = _kvService.CreateKey(keyId);
            var key = new SymmetricSecurityKey(Convert.FromBase64String(payload)) { KeyId = keyId };
            string client = ((Client?)HttpContext.Items["client"])!.Name ?? "";

            if (await _database.CreateAccount(account))
            {
                foreach(string item in "user reset delete".Split(" "))
                {
                    var res = await _database.CreateAccept(id, (HttpContext.Items["client"] as Client)?.Name ?? "", item);
                }
                
                if (await _database.CreateAuthKey(key.KeyId, _audience, id))
                {
                    var result = new
                    {
                        id_token = CreateIdToken(account.Identity.Claims, key, client),
                        refresh_token = CreateRefreshToken(id, key, client)
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
        [Client]
        [AllowAnonymous]
        [HttpPost("token")]
        public async Task<ActionResult> CreateToken([FromForm] string? scope, [FromForm] string code, [FromForm] string verifier)
        {
            Client? client = (Client?)HttpContext.Items["client"];
            if (client == null)
            {
                return BadRequest("Невозможно получить данные о клиентском приложении");
            }
            Request? request = await _database.GetRequestByCode(code);
            if (request != null)
            {
                byte[] hashVerifier = HashCode(verifier);
                if (IsHashCodeValid(hashVerifier, Encoding.UTF8.GetBytes(request.Verifier)))
                {
                    string keyId = Guid.NewGuid().ToString();
                    string payload = _kvService.CreateKey(keyId);
                    var key = new SymmetricSecurityKey(Convert.FromBase64String(payload)) { KeyId = keyId };
                    if (!await _database.CreateAuthKey(key.KeyId, _audience, request.User))
                    {
                        return Problem("Новый ключ подписи не создан в базе данных");
                    }

                    StringBuilder validScopes = new();
                    List<string> acceptedScopes = await _database.GetAccepts(request.User, client.Name ?? "");
                    if (!string.IsNullOrEmpty(scope))
                    {
                        validScopes.AppendJoin(" ", client.Scopes.Intersect(acceptedScopes).Intersect(scope.Split(" ")));
                    }
                    else
                    {
                        validScopes.AppendJoin(" ", client.Scopes.Intersect(acceptedScopes));
                    }

                    string access = CreateAccessToken(request.User, key, validScopes.ToString(), client.Name ?? "");
                    string refresh = CreateRefreshToken(request.User, key, client.Name ?? "");
                    var result = new
                    {
                        access_token = access,
                        refresh_token = refresh
                    };
                    return Ok(result);
                }
                else
                {
                    return BadRequest("Запрос не авторизован системой");
                }
            }
            else
            {
                return BadRequest("Неправильный запрос");
            }
        }
        [Client]
        [HttpPost("token/refresh")]
        public async Task<ActionResult> GetToken([FromForm] string scope)
        {
            var auth = await HttpContext.AuthenticateAsync();
            var tokenScope = auth.Ticket?.Principal?.FindFirstValue("scope") ?? "";
            if (!tokenScope.Contains("refresh"))
            {
                return BadRequest("Представленный токен не предназначен для доступа к этому ресурсу");
            }
            var token = auth.Properties?.GetTokens().First().Value;
            var handler = new JwtSecurityTokenHandler();
            var kid = handler.ReadJwtToken(token).Header.Kid;
            if (await _database.IsKeyValid(kid))
            {
                if (!_kvService.DeleteKey(kid))
                {
                    return Problem("Хранилище секретов не удалило ключ");
                }
                if (!await _database.DeleteAuthKey(kid))
                {
                    return Problem("База данных не удалила идентификатор ключа");
                }
                Client? client = (Client?)HttpContext.Items["client"];
                string user = HttpContext.User.FindFirstValue(ClaimTypes.SerialNumber) ?? "";
                string keyId = Guid.NewGuid().ToString();
                string payload = _kvService.CreateKey(keyId);
                var key = new SymmetricSecurityKey(Convert.FromBase64String(payload)) { KeyId = keyId };
                if (!await _database.CreateAuthKey(key.KeyId, _audience, user))
                {
                    return Problem("Новый ключ подписи не создан в базе данных");
                }

                StringBuilder validScopes = new();
                List<string> acceptedScopes = await _database.GetAccepts(user, client?.Name ?? "");
                if (!string.IsNullOrEmpty(scope))
                {
                    validScopes.AppendJoin(" ", client!.Scopes.Intersect(acceptedScopes).Intersect(scope.Split(" ")));
                }
                else
                {
                    validScopes.AppendJoin(" ", client!.Scopes.Intersect(acceptedScopes));
                }

                string access = CreateAccessToken(user, key, validScopes.ToString(), client.Name ?? "");
                string refresh = CreateRefreshToken(user, key, client.Name ?? "");
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
        [TrustClient]
        [HttpGet("token/reset")]
        public async Task<ActionResult> GetResetToken()
        {
            var auth = await HttpContext.AuthenticateAsync();
            var tokenScope = auth.Ticket?.Principal?.FindFirstValue("scope") ?? "";
            if (!tokenScope.Contains("refresh"))
            {
                return BadRequest("Представленный токен не предназначен для доступа к этому ресурсу");
            }
            var token = auth.Properties?.GetTokens().First().Value;
            var handler = new JwtSecurityTokenHandler();
            var kid = handler.ReadJwtToken(token).Header.Kid;
            if (await _database.IsKeyValid(kid))
            {
                if (!_kvService.DeleteKey(kid))
                {
                    return Problem("Хранилище секретов не удалило ключ");
                }
                if (!await _database.DeleteAuthKey(kid))
                {
                    return Problem("База данных не удалила идентификатор ключа");
                }
                Client? client = (Client?)HttpContext.Items["client"];
                string user = HttpContext.User.FindFirstValue(ClaimTypes.SerialNumber) ?? "";
                string keyId = Guid.NewGuid().ToString();
                string payload = _kvService.CreateKey(keyId);
                var key = new SymmetricSecurityKey(Convert.FromBase64String(payload)) { KeyId = keyId };
                if (!await _database.CreateAuthKey(key.KeyId, _audience, user))
                {
                    return Problem("Новый ключ подписи не создан в базе данных");
                }

                StringBuilder validScopes = new();
                List<string> acceptedScopes = await _database.GetAccepts(user, client?.Name ?? "");
                validScopes.AppendJoin(" ", client!.Scopes.Intersect(acceptedScopes).Intersect("reset".Split(" ")));

                string access = CreateAccessToken(user, key, validScopes.ToString(), client.Name ?? "");
                string refresh = CreateRefreshToken(user, key, client.Name ?? "");
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
        [TrustClient]
        [HttpGet("token/accept")]
        public async Task<ActionResult> GetAcceptToken()
        {
            var auth = await HttpContext.AuthenticateAsync();
            var tokenScope = auth.Ticket?.Principal?.FindFirstValue("scope") ?? "";
            if (!tokenScope.Contains("refresh"))
            {
                return BadRequest("Представленный токен не предназначен для доступа к этому ресурсу");
            }
            var token = auth.Properties?.GetTokens().First().Value;
            var handler = new JwtSecurityTokenHandler();
            var kid = handler.ReadJwtToken(token).Header.Kid;
            if (await _database.IsKeyValid(kid))
            {
                if (!_kvService.DeleteKey(kid))
                {
                    return Problem("Хранилище секретов не удалило ключ");
                }
                if (!await _database.DeleteAuthKey(kid))
                {
                    return Problem("База данных не удалила идентификатор ключа");
                }
                Client? client = (Client?)HttpContext.Items["client"];
                string user = HttpContext.User.FindFirstValue(ClaimTypes.SerialNumber) ?? "";
                string keyId = Guid.NewGuid().ToString();
                string payload = _kvService.CreateKey(keyId);
                var key = new SymmetricSecurityKey(Convert.FromBase64String(payload)) { KeyId = keyId };
                if (!await _database.CreateAuthKey(key.KeyId, _audience, user))
                {
                    return Problem("Новый ключ подписи не создан в базе данных");
                }

                StringBuilder validScopes = new();
                List<string> acceptedScopes = await _database.GetAccepts(user, client?.Name ?? "");
                validScopes.AppendJoin(" ", client!.Scopes.Intersect(acceptedScopes).Intersect("accept".Split(" ")));

                string access = CreateAccessToken(user, key, validScopes.ToString(), client.Name ?? "");
                string refresh = CreateRefreshToken(user, key, client.Name ?? "");
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
        [TrustClient]
        [HttpPost("flow")]
        public async Task<ActionResult> CreateAuthorizationFlow([FromForm] string code_verifier, [FromForm] string secret, [FromForm] string scope, [FromForm] string client, [FromForm] string user)
        {
            if (!await Client.Authenticate(_database, client, secret))
            {
                return BadRequest("Клиентское приложение не авторизовано");
            }
            Request request = new()
            {
                Client = client,
                Scope = scope,
                Code = Convert.ToBase64String(RandomNumberGenerator.GetBytes(64)),
                Verifier = code_verifier,
                User = user
            };
            if (await _database.CreateRequest(request))
            {
                return Accepted();
            }
            else
            {
                return Problem("База данных не выполнила запрос");
            }
        }
        [Client]
        [HttpDelete("token")]
        public async Task<ActionResult> RevokeToken()
        {
            var auth = await HttpContext.AuthenticateAsync();
            var scope = auth.Ticket?.Principal?.FindFirstValue("scope") ?? "";
            if (!scope.Contains("refresh"))
            {
                return BadRequest("Полученный токен не предназначен для доступа к этому ресурсу");
            }
            var token = auth.Properties?.GetTokens().First().Value;
            var handler = new JwtSecurityTokenHandler();
            var kid = handler.ReadJwtToken(token).Header.Kid;
            if (!_kvService.DeleteKey(kid))
            {
                return Problem("Ключ подписи не удалён из озера ключей");
            }
            if (!await _database.DeleteAuthKey(kid))
            {
                return Problem("Идентификатор ключа подписи не удалён из базы данных");
            }
            return Accepted();
        }
        [TrustClient]
        [HttpGet("accept")]
        public async Task<ActionResult> AcceptData([FromQuery] string issuer, [FromQuery] string scope)
        {
            AuthenticateResult authResult = await HttpContext.AuthenticateAsync();
            string tokenScope = authResult.Ticket?.Principal?.FindFirstValue("scope") ?? "";
            if (!tokenScope.Contains("accept"))
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
                if (await _database.CreateAccept(user_id, issuer, scope))
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
        [TrustClient]
        [HttpGet("revoke")]
        public async Task<ActionResult> RevokeData([FromQuery] string issuer, [FromQuery] string? scope)
        {
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
                if (string.IsNullOrEmpty(scope))
                {
                    if (await _database.DeleteAccept(user_id, issuer))
                    {
                        return Ok();
                    }
                }
                else
                {
                    if (await _database.DeleteAccept(user_id, issuer, scope))
                    {
                        return Ok();
                    }
                }
                return Problem();
                
            }
            catch (Exception)
            {
                return Problem();
            }
        }
        [Client]
        [HttpGet("signout")]
        public async Task<ActionResult> UserSignOut()
        {
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
                _kvService.DeleteKey(key);
            if (await _database.DeleteUserAuthKeys(id))
            {
                return Ok();
            }
            else
            {
                return Problem("Не удалось выполнить выход");
            }
        }
        [TrustClient]
        [HttpPost("reset")]
        public async Task<ActionResult> ResetPassword([FromForm] string password)
        {
            var auth = await HttpContext.AuthenticateAsync();
            var scope = auth.Ticket?.Principal?.FindFirstValue("scope") ?? "";
            if (!scope.Contains("reset"))
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
            using var argon2 = new Argon2id(_password)//Recommended parameters by OWASP
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
            //argon2 = null;//Releases memmory (without leak)
            GC.Collect();

            return hash;
        }
        private static byte[] HashCode(string code)
        {
            return SHA256.HashData(Encoding.UTF8.GetBytes(code));
        }
        private static bool IsHashCodeValid(byte[] actual, byte[] expected)
        {
            return expected.SequenceEqual(actual);
        }
        private static bool IsHashValid(byte[] hash, string db_hash) => hash.SequenceEqual(Convert.FromBase64String(db_hash));
        private string CreateIdToken(IEnumerable<Claim> claims, SymmetricSecurityKey key, string audience)
        {
            _ = claims.Append(new Claim("scope", "id", ClaimValueTypes.String, _issuer));
            var token = CreateToken(claims, key, TimeSpan.FromHours(10), audience);
            return token;
        }
        private string CreateRefreshToken(string guid, SymmetricSecurityKey key, string audience)
        {
            var claims = new List<Claim>() { 
                new Claim(ClaimTypes.SerialNumber, guid, ClaimValueTypes.String, _issuer),
                new Claim("scope", "refresh accept", ClaimValueTypes.String, _issuer)
            };
            var token = CreateToken(claims, key, TimeSpan.FromDays(14), audience);
            return token;
        }
        private string CreateAccessToken(string guid, SymmetricSecurityKey key, string scope, string audience)
        {
            var claims = new List<Claim>() {
                new Claim(ClaimTypes.SerialNumber, guid, ClaimValueTypes.String, _issuer),
                new Claim("scope", scope, ClaimValueTypes.String, _issuer)
            };
            var token = CreateToken(claims, key, TimeSpan.FromHours(1), audience);
            return token;
        }
        private string CreateToken(IEnumerable<Claim> claims, SymmetricSecurityKey key, TimeSpan lifetime, string audience)
        {
            var now = DateTime.UtcNow;
            var jwt = new JwtSecurityToken(
                _issuer,
                audience,
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
