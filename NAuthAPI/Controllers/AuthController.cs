using Microsoft.AspNetCore.Http;
using Microsoft.AspNetCore.Mvc;
using Microsoft.AspNetCore.SignalR;
using System.Net;
using Ydb.Sdk.Auth;
using Ydb.Sdk;
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
using System.Globalization;

namespace NAuthAPI.Controllers
{
    [Authorize]
    [Route("auth")]
    [ApiController]
    public class AuthController(IConfiguration configuration, IAppContext db, IKVEngine kvService) : ControllerBase
    {
        readonly IKVEngine _kvService = kvService;
        readonly string _pepper = kvService.GetPepper();
        readonly string issuer = configuration["Issuer"] ?? "NAuth API";
        readonly string audience = configuration["Audience"] ?? "NAuth App";

        #region Endpoints Logic
        /// <summary>
        /// Выполняет вход пользователя с предоставленными атрибутами аутентификации от имени доверенного клиентского приложения
        /// </summary>
        /// <param name="username">Имя пользователя</param>
        /// <param name="password">Пароль пользователя</param>
        /// <returns>Возвращает токен обновления для доступа на специальные конечные точки</returns>
        /// <exception cref="Exception"></exception>
        [TrustClient]
        [AllowAnonymous]
        [HttpPost("signin")]
        public async Task<ActionResult> SignIn([FromForm] string username, [FromForm] string password)
        {
            if (string.IsNullOrEmpty(username) || string.IsNullOrEmpty(password))
            {
                return BadRequest("Невозможно выполнить вход с пустыми идентификатором и паролем");
            }
            if (username.Length > 64 || password.Length > 32)
            {
                return BadRequest("Превышено количество символов в логине или пароле");
            }

            Account? account = await db.GetAccount(username);
            if (account == null)
            {
                return Unauthorized("Учётная запись не существует");
            }

            if (account.IsBlocked)
            {
                return Forbid();
            }

            int failedAttempts = 0;
            foreach(var attempt in await db.GetAttempts(account.Id))
            {
                if (!attempt.Success) failedAttempts++;
            }
            if (failedAttempts > 2)
            {
                return Forbid();
            }

            byte[] hash = await HashPassword(password, account.Id, account.Salt);
            if (account.Hash == null)
            {
                return Forbid();
            }

            bool success = IsHashValid(hash, account.Hash);
            if (!await db.AddAttempt(account.Id, success))
            {
                return Problem("Невозможно засчитать попытку входа");
            }
            if (!success)
            {
                return Unauthorized("Неправильный логин или пароль");
            }

            string keyId = Guid.NewGuid().ToString();
            byte[] payload = _kvService.CreateKey(keyId);
            var key = new SymmetricSecurityKey(payload) { KeyId = keyId };
            string client = (string?)HttpContext.Items["client"] ?? throw new Exception("Нет объекта клиентского приложения");
            if (await db.CreateAuthKey(keyId, audience, account.Id))
            {
                var result = new
                {
                    refresh_token = CreateRefreshToken(account.Id, key, client)
                };
                return Ok(result);
            }
            return NoContent();
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
            }
            else
            {
                return BadRequest("Невозможно создать учётную запись без идентификатора и пароля");
            }

            if (string.IsNullOrEmpty(username) || string.IsNullOrEmpty(password))
            {
                return BadRequest("Нельзя создать учётную запись с пустыми идентификатором и паролем");
            }
            if (username.Length > 64 || password.Length > 32)
            {
                return BadRequest("Превышено количество символов в логине или пароле");
            }

            string id = Guid.NewGuid().ToString();
            byte[] salt = CreateSalt();
            byte[] hash = await HashPassword(password, id, salt);

            foreach(var formKey in form.Keys)
            {
                if (string.IsNullOrEmpty(formKey))
                {
                    continue;
                }
                var value = form[formKey].First();
                if (string.IsNullOrEmpty(value))
                {
                    continue;
                }
                if (value.Length > 128)
                {
                    throw new Exception($"Превышение ограничения символов для атрибута {formKey}");
                }
            }
            string? phone_str = form["phone"].FirstOrDefault();
            ulong? phone = phone_str != null ? ulong.Parse(phone_str) : null;
            User user = new(id,
                form["surname"].FirstOrDefault(),
                form["name"].FirstOrDefault(),
                form["lastname"].FirstOrDefault(),
                form["email"].FirstOrDefault(),
                phone,
                form["gender"].FirstOrDefault());
            Account account = new(id, username, hash, salt, false, "user", DateTime.Now.AddYears(1));

            string keyId = Guid.NewGuid().ToString();
            byte[] payload = _kvService.CreateKey(keyId);
            var key = new SymmetricSecurityKey(payload) { KeyId = keyId };

            string client = (string?)HttpContext.Items["client"] ?? throw new Exception("Нет объекта клиентского приложения");

            if (!await db.CreateIdentity(account, user))
            {
                return Problem("Не удалось зарегистрировать пользователя");
            }
            if (!await db.CreateAccept(id, client, "user reset delete"))
            {
                return Problem("Не удалось присвоить основные разрешения на управление учётной записью пользователя");
            }
            if (await db.CreateAuthKey(key.KeyId, audience, id))
            {
                var result = new
                {
                    refresh_token = CreateRefreshToken(id, key, client)
                };
                return Ok(result);
            }
            return Accepted();
        }
        [Client]
        [HttpGet("token/access")]
        public async Task<ActionResult> GetAccessToken()
        {
            var auth = await HttpContext.AuthenticateAsync();
            var tokenScope = auth.Ticket?.Principal?.FindFirstValue("scope") ?? "";
            if (!tokenScope.Contains("refresh"))
            {
                return BadRequest("Представленный токен не предназначен для доступа к этому ресурсу");
            }
            string client = (string?)HttpContext.Items["client"] ?? throw new Exception("Нет объекта клиентского приложения");
            
            string user = HttpContext.User.FindFirstValue(ClaimTypes.SerialNumber) ?? throw new Exception("В токене не представлен идентификатор пользователя");

            string keyId = Guid.NewGuid().ToString();
            byte[] payload = _kvService.CreateKey(keyId);
            var key = new SymmetricSecurityKey(payload) { KeyId = keyId };
            if (!await db.CreateAuthKey(key.KeyId, audience, user))
            {
                return Problem("Новый ключ подписи не создан в базе данных");
            }

            StringBuilder validScopes = new();
            List<string> acceptedScopes = await db.GetAccepts(user, client);
            validScopes.AppendJoin(" ", acceptedScopes);

            var result = new
            {
                access_token = CreateAccessToken(user, key, validScopes.ToString(), client),
                refresh_token = CreateRefreshToken(user, key, client)
            };
            return Ok(result);
        }
        [Client]
        [AllowAnonymous]
        [HttpPost("authorize")]
        public async Task<ActionResult> CreateToken([FromForm] string code, [FromForm] string verifier)
        {
            string client = (string?)HttpContext.Items["client"] ?? throw new Exception("Нет объекта клиентского приложения");
            
            Request? request = await db.GetRequestByCode(code);
            if (request == null)
            {
                return BadRequest("Запрос не найден в базе данных");
            }

            byte[] hashVerifier = HashCode(verifier);
            if (!IsHashValid(hashVerifier, Encoding.UTF8.GetBytes(request.Verifier)))
            {
                return BadRequest("Запрос не авторизован");
            }
            if (!await db.DeleteRequest(code))
            {
                return Problem("Авторизационный код не удалён в базе данных");
            }

            string keyId = Guid.NewGuid().ToString();
            byte[] payload = _kvService.CreateKey(keyId);
            var key = new SymmetricSecurityKey(payload) { KeyId = keyId };
            if (!await db.CreateAuthKey(key.KeyId, audience, request.User))
            {
                return Problem("Новый ключ подписи не создан в базе данных");
            }
            
            StringBuilder validScopes = new();
            List<string> acceptedScopes = await db.GetAccepts(request.User, client);
            validScopes.AppendJoin(" ", acceptedScopes);

            var result = new
            {
                access_token = CreateAccessToken(request.User, key, validScopes.ToString(), client),
                refresh_token = CreateRefreshToken(request.User, key, client)
            };
            return Ok(result);
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
            if (!await db.IsKeyValid(kid))
            {
                return Unauthorized();
            }
            if (!_kvService.DeleteKey(kid))
            {
                return Problem("Хранилище секретов не удалило ключ");
            }
            if (!await db.DeleteAuthKey(kid))
            {
                return Problem("База данных не удалила идентификатор ключа");
            }
            string? client = (string?)HttpContext.Items["client"] ?? string.Empty;
            string user = HttpContext.User.FindFirstValue(ClaimTypes.SerialNumber) ?? "";
            string keyId = Guid.NewGuid().ToString();
            byte[] payload = _kvService.CreateKey(keyId);
            var key = new SymmetricSecurityKey(payload) { KeyId = keyId };
            if (!await db.CreateAuthKey(key.KeyId, audience, user))
            {
                return Problem("Новый ключ подписи не создан в базе данных");
            }

            StringBuilder validScopes = new();
            List<string> acceptedScopes = await db.GetAccepts(user, client);
            validScopes.AppendJoin(" ", acceptedScopes.Intersect(["reset"]));

            var result = new
            {
                access_token = CreateAccessToken(user, key, validScopes.ToString(), client),
                refresh_token = CreateRefreshToken(user, key, client)
            };
            return Ok(result);
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
            if (!await db.IsKeyValid(kid))
            {
                return Unauthorized();
            }
            if (!_kvService.DeleteKey(kid))
            {
                return Problem("Хранилище секретов не удалило ключ");
            }
            if (!await db.DeleteAuthKey(kid))
            {
                return Problem("База данных не удалила идентификатор ключа");
            }
            string client = (string?)HttpContext.Items["client"] ?? throw new Exception("Нет объекта клиентского приложения");
            string user = HttpContext.User.FindFirstValue(ClaimTypes.SerialNumber) ?? "";
            string keyId = Guid.NewGuid().ToString();
            byte[] payload = _kvService.CreateKey(keyId);
            var securityKey = new SymmetricSecurityKey(payload) { KeyId = keyId };
            if (!await db.CreateAuthKey(keyId, audience, user))
            {
                return Problem("Новый ключ подписи не создан в базе данных");
            }

            StringBuilder validScopes = new();
            List<string> acceptedScopes = await db.GetAccepts(user, client);
            validScopes.AppendJoin(" ", acceptedScopes.Intersect(["accept"]));

            var result = new
            {
                access_token = CreateAccessToken(user, securityKey, validScopes.ToString(), client),
                refresh_token = CreateRefreshToken(user, securityKey, client)
            };
            return Ok(result);
        }
        [TrustClient]
        [HttpPost("flow")]
        public async Task<ActionResult> CreateFlow([FromForm] string code_verifier, [FromForm] string scope, [FromForm] string client)
        {
            if (!await ClientValidator.IsValidClient(db, client))
            {
                return BadRequest("Клиентское приложение не авторизовано");
            }
            Request request = new()
            {
                Client = client,
                Scope = scope,
                Code = Convert.ToBase64String(RandomNumberGenerator.GetBytes(64)),
                User = HttpContext.User.FindFirstValue(ClaimTypes.SerialNumber) ?? "",
                Verifier = code_verifier
            };
            if (await db.CreateRequest(request))
            {
                var result = new
                {
                    code = request.Code
                };
                return Ok(result);
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
                return Problem("Ключ подписи не удалён из хранилища ключей");
            }
            if (!await db.DeleteAuthKey(kid))
            {
                return Problem("Идентификатор ключа подписи не удалён из базы данных");
            }
            return Accepted();
        }
        [TrustClient]
        [HttpGet("accept")]
        public async Task<ActionResult> AcceptScope([FromQuery] string client, [FromQuery] string scope)
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

            if (await db.CreateAccept(user_id, client, scope))
            {
                return Accepted();
            }
            else
            {
                return Problem("Фиксация разрешения в базе данных не произошла");
            }
        }
        [TrustClient]
        [HttpDelete("accept")]
        public async Task<ActionResult> RevokeScope([FromQuery] string client, [FromQuery] string scope)
        {
            AuthenticateResult authResult = await HttpContext.AuthenticateAsync();
            string tokenScope = authResult.Ticket?.Principal?.FindFirstValue("scope") ?? "";
            if (!tokenScope.Contains("refresh"))
            {
                return BadRequest("Полученный токен не предназначен для доступа к этому ресурсу");
            }
            string user = HttpContext.User.FindFirst(ClaimTypes.SerialNumber)?.Value ?? "";
            if (string.IsNullOrEmpty(user))
            {
                return BadRequest("Токен не содержит идентификационную информацию");
            }
            try
            {
                if (string.IsNullOrEmpty(scope))
                {
                    if (await db.DeleteAccept(user, client))
                    {
                        return Ok();
                    }
                }
                else
                {
                    if (await db.DeleteAccept(user, client, scope))
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

            var keys = await db.GetUserKeys(id);
            foreach (var key in keys)
            {
                _kvService.DeleteKey(key);
            }

            if (await db.DeleteUserAuthKeys(id))
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
            if (await db.SetPasswordHash(id, hash))
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

        private static byte[] CreateSalt() => CreateRandBytes(32);
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
            //argon2 = null;//Correct releasing memmory 
            GC.Collect();

            return hash;
        }

        private static byte[] HashCode(string code) => SHA256.HashData(Encoding.UTF8.GetBytes(code));
        private static bool IsHashValid(byte[] actual, byte[] expected) => expected.SequenceEqual(actual);
        
        private string CreateRefreshToken(string id, SymmetricSecurityKey key, string audience)
        {
            var claims = new List<Claim>() { 
                new(ClaimTypes.SerialNumber, id, ClaimValueTypes.String, issuer),
                new("scope", "refresh", ClaimValueTypes.String, issuer)
            };
            var token = CreateToken(claims, key, TimeSpan.FromDays(7), audience);
            return token;
        }
        private string CreateAccessToken(string guid, SymmetricSecurityKey key, string scope, string audience)
        {
            var claims = new List<Claim>() {
                new(ClaimTypes.SerialNumber, guid, ClaimValueTypes.String, issuer),
                new("scope", scope, ClaimValueTypes.String, issuer)
            };
            var token = CreateToken(claims, key, TimeSpan.FromMinutes(10), audience);
            return token;
        }

        private string CreateToken(IEnumerable<Claim> claims, SymmetricSecurityKey key, TimeSpan lifetime, string audience)
        {
            var now = DateTime.UtcNow;
            var jwt = new JwtSecurityToken(
                issuer,
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
