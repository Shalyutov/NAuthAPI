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
        [AllowAnonymous]
        [HttpPost("signin")]
        public async Task<ActionResult> SignIn([FromForm] string username, [FromForm] string password, [FromHeader] string client_id, [FromHeader] string client_secret)
        {
            if (!IsDBInitialized)
                return Problem("Драйвер базы данных не инициализирован");
            var client = await Client.GetClientAsync(_database, client_id, client_secret);
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
                    return Unauthorized("Неправильный логин или пароль");
                if (account.IsBlocked)
                    return Forbid();
                if (account.Attempts > 2)
                    return Forbid();
                var guid = account.Identity.FindFirst(ClaimTypes.SerialNumber)?.Value ?? "";
                var hash = await HashPassword(password, guid, Convert.FromBase64String(account.Salt));
                if (IsHashValid(hash, account.Hash))
                {
                    await _database.NullAttempt(guid);
                    var bytes = CreateRandBytes(32);
                    var key = await CryptoIO.CreateSecurityKey(bytes);
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
                    await _database.AddAttempt(guid);
                    return Unauthorized("Неправильный логин или пароль");
                }
            }
            catch (Exception ex)
            {
                return Problem(ex.Message);
            }
        }
        [AllowAnonymous]
        [HttpPost("signup")]
        public async Task<ActionResult> SignUp([FromHeader] string client_id, [FromHeader] string client_secret)
        {
            if (!IsDBInitialized) 
                return Problem("Драйвер базы данных не инициализирован");
            var client = await Client.GetClientAsync(_database, client_id, client_secret);
            if (client == null)
                return BadRequest("Клиентское приложение не авторизовано");
            if (!client.IsImplementation) 
                return BadRequest("Клиент не имеет доверенной реализации потока системы");
            if (!HttpContext.Request.HasFormContentType)
                return BadRequest("Нет утверждений для изменения");
            var form = await HttpContext.Request.ReadFormAsync();
            if (!form.ContainsKey("username") || !form.ContainsKey("password"))
                return BadRequest("Нельзя создать учётную запись без идентификатора и пароля");
            if (form["username"] == "" || form["password"] == "") 
                return BadRequest("Нельзя создать учётную запись с пустыми идентификатором и паролем");

            string guid = Guid.NewGuid().ToString();
            var salt = CreateSalt();
            string hash = Convert.ToBase64String(await HashPassword(form["password"].First() ?? "", guid, salt));

            var claims = new List<Claim>()
            {
                new Claim(ClaimTypes.Upn, form["username"].First() ?? "", ClaimValueTypes.String, _issuer),
                new Claim(ClaimTypes.SerialNumber, guid, ClaimValueTypes.String, _issuer)
            };
            foreach(var formKey in form.Keys)
            {
                if (string.IsNullOrEmpty(formKey)) continue;
                Claim? claim = null;
                switch (formKey)
                {
                    case "surname":
                        claim = new Claim(ClaimTypes.Surname, form[formKey].First() ?? "", ClaimValueTypes.String, _issuer);
                        break;
                    case "name":
                        claim = new Claim(ClaimTypes.Name, form[formKey].First() ?? "", ClaimValueTypes.String, _issuer);
                        break;
                    case "lastname":
                        claim = new Claim("LastName", form[formKey].First() ?? "", ClaimValueTypes.String, _issuer);
                        break;
                    case "email":
                        claim = new Claim(ClaimTypes.Email, form[formKey].First() ?? "", ClaimValueTypes.String, _issuer);
                        break;
                    case "gender":
                        claim = new Claim(ClaimTypes.Gender, form[formKey].First() ?? "", ClaimValueTypes.String, _issuer);
                        break;
                    case "phone":
                        claim = new Claim(ClaimTypes.MobilePhone, form[formKey].First() ?? "", ClaimValueTypes.UInteger64, _issuer);
                        break;
                };
                if (claim != null) claims.Add(claim);
            }
            ClaimsIdentity identity = new(claims);
            Account account = new(identity, hash, Convert.ToBase64String(salt), false, 0);

            var bytes = CreateRandBytes(32);
            var key = await CryptoIO.CreateSecurityKey(bytes);
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
        [HttpGet("token")]
        public async Task<ActionResult> Token([FromHeader] string client_id, [FromHeader] string client_secret)
        {
            if (!IsDBInitialized)
                return Problem("Драйвер базы данных не инициализирован");
            var client = await Client.GetClientAsync(_database, client_id, client_secret);
            if (client == null)
                return BadRequest("Клиентское приложение не авторизовано");

            var auth = await HttpContext.AuthenticateAsync();
            var scope = auth.Ticket?.Principal?.FindFirstValue("scope") ?? "";
            if (!scope.Contains("refresh"))
                return BadRequest("Полученный токен не предназначен для доступа к этому ресурсу");

            var token = auth.Ticket?.Properties.GetTokens().First().Value;
            
            var handler = new JwtSecurityTokenHandler();
            var id = handler.ReadJwtToken(token).Header.Kid;
            
            var isValid = await _database.IsKeyValid(id);
            if (isValid)
            {
                CryptoIO.DeleteSecurityKey(id);
                var db_res = await _database.DeleteAuthKey(id);
                if (!db_res) return Problem("Запрос к базе данных не выполнен");
                var bytes = CreateRandBytes(32);
                var key = await CryptoIO.CreateSecurityKey(bytes);
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
        [HttpGet("signout/this")]
        public async Task<ActionResult> Revoke([FromHeader] string client_id, [FromHeader] string client_secret)
        {
            if (!IsDBInitialized)
                return Problem("Драйвер базы данных не инициализирован");
            var client = await Client.GetClientAsync(_database, client_id, client_secret);
            if (client == null)
                return BadRequest("Клиентское приложение не авторизовано");

            var auth = await HttpContext.AuthenticateAsync();
            var scope = auth.Ticket?.Principal?.FindFirstValue("scope") ?? "";
            if (!scope.Contains("refresh"))
                return BadRequest("Полученный токен не предназначен для доступа к этому ресурсу");
            var token = auth.Properties?.GetTokens().First().Value;
            var handler = new JwtSecurityTokenHandler();
            var kid = handler.ReadJwtToken(token).Header.Kid;
            try
            {
                CryptoIO.DeleteSecurityKey(kid);
                var res = await _database.DeleteAuthKey(kid);
                if (res)
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
        public async Task<ActionResult> SignOut([FromHeader] string client_id, [FromHeader] string client_secret)
        {
            if (!IsDBInitialized)
                return Problem("Драйвер базы данных не инициализирован");
            var client = await Client.GetClientAsync(_database, client_id, client_secret);
            if (client == null)
                return BadRequest("Клиентское приложение не авторизовано");

            var auth = await HttpContext.AuthenticateAsync();
            var scope = auth.Ticket?.Principal?.FindFirstValue("scope") ?? "";
            if (!scope.Contains("refresh"))
                return BadRequest("Полученный токен не предназначен для доступа к этому ресурсу");

            var user = HttpContext.User.FindFirst(ClaimTypes.SerialNumber)?.Value;
            if (user == null) return BadRequest("Нет идентификационной информации в токене");
            try
            {
                var keys = await _database.GetUserKeys(user);
                foreach (var key in keys) CryptoIO.DeleteSecurityKey(key);
                var res = await _database.DeleteUserAuthKeys(user);
                if (res)
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
        #endregion
        #region Private Logic
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
