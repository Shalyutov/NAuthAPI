using Microsoft.AspNetCore.Authentication;
using Microsoft.AspNetCore.Authorization;
using Microsoft.AspNetCore.Http;
using Microsoft.AspNetCore.Mvc;
using System.Security.Claims;

namespace NAuthAPI.Controllers
{
    [Authorize]
    [Route("user")]
    [ApiController]
    public class UserController : ControllerBase
    {
        readonly AppContext _database;
        readonly KeyLakeService _lakeService;
        private bool IsDBInitialized => _database != null;
        public UserController(AppContext db, KeyLakeService lakeService)
        {
            _database = db;
            _lakeService = lakeService;
        }
        #region Endpoints Logic
        [HttpGet("account")]
        public async Task<ActionResult> GetAccount([FromHeader] string client, [FromHeader] string secret)
        {
            if (!IsDBInitialized)
            {
                return Problem("Драйвер базы данных не инициализирован");
            }
                
            Client? _client = await Client.GetClientAsync(_database, client, secret);
            if (_client == null)
            {
                return BadRequest("Клиентское приложение не авторизовано");
            }

            string id = HttpContext.User.FindFirst(ClaimTypes.SerialNumber)?.Value ?? "";
            string scope = HttpContext.User.FindFirst("scope")?.Value ?? "";
            Account? account = await _database.GetAccountById(id);
            if (account != null)
            {
                Dictionary<string, string> claims = new();
                foreach (var claim in account.Identity.Claims)
                {
                    string type = claim.Type switch
                    {
                        ClaimTypes.Upn => "username",
                        ClaimTypes.Surname => "surname",
                        ClaimTypes.Name => "name",
                        ClaimTypes.Email => "email",
                        ClaimTypes.MobilePhone => "phone",
                        ClaimTypes.Gender => "gender",
                        ClaimTypes.SerialNumber => "guid",
                        _ => claim.Type
                    };
                    if (scope.Contains("user") ||
                        scope.Contains($"user:{type}") ||
                        scope.Contains($"user:{type}:get"))
                    {
                        claims.Add(type, claim.Value);
                    }
                }
                return Ok(claims);
            }
            else
            {
                return NoContent();
            }
        }

        [HttpGet("claims")]
        public async Task<ActionResult> GetClaims([FromForm] string claims, [FromHeader] string client, [FromHeader] string secret)
        {
            if (!IsDBInitialized)
            {
                return Problem("Драйвер базы данных не инициализирован");
            }

            Client? _client = await Client.GetClientAsync(_database, client, secret);
            if (_client == null)
            {
                return BadRequest("Клиентское приложение не авторизовано");
            }

            string id = HttpContext.User.FindFirst(ClaimTypes.SerialNumber)?.Value ?? "";
            List<string> validScopes = (HttpContext.User.FindFirst("scope")?.Value ?? "").Split(" ").ToList();
            List<string> requiredScopes = claims.Split(" ").ToList();
            
            List<Claim> 
            if (_claims.Count > 0)
            {
                return Ok(_claims);
            }
            else
            {
                return NoContent();
            }
        }
        [HttpPut("account")]
        public async Task<ActionResult> UpdateAccount([FromHeader] string client_id, [FromHeader] string client_secret)
        {
            if (!IsDBInitialized)
                return Problem("Драйвер базы данных не инициализирован");
            var client = await Client.GetClientAsync(_database, client_id, client_secret);
            if (client == null)
                return BadRequest("Клиентское приложение не авторизовано");
            if (!HttpContext.Request.HasFormContentType)
                return BadRequest("Запрос не представляет форму для измененния данных");
            var auth = await HttpContext.AuthenticateAsync();
            var scope = auth.Ticket?.Principal?.FindFirstValue("scope") ?? string.Empty;
            if (!scope.Contains("user")) 
                return BadRequest("Полученный токен не предназначен для доступа к этому ресурсу");
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
        [HttpDelete("account")]
        public async Task<ActionResult> DeleteUser([FromHeader] string client, [FromHeader] string secret)
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

            var scope = HttpContext.User.FindFirstValue("scope") ?? string.Empty;
            if (!scope.Contains("user"))
            {
                return BadRequest("Полученный токен не предназначен для доступа к этому ресурсу");
            }
                
            var id = HttpContext.User.FindFirst(ClaimTypes.SerialNumber)?.Value ?? "";
            
            var keys = await _database.GetUserKeys(id);
            foreach (var key in keys)
                await _lakeService.DeleteKey(key);
            await _database.DeleteUserAuthKeys(id);

            if (await _database.DeleteAccount(id))
            {
                return Ok();
            }
            else
            {
                return Problem("Не удалось удалить учётную запись");
            }
        }
        [AllowAnonymous]
        [HttpGet("account/exists")]
        public async Task<ActionResult> IsUserExists([FromQuery] string username, [FromHeader] string client_id, [FromHeader] string client_secret)
        {
            if (!IsDBInitialized)
                return Problem("Драйвер базы данных не инициализирован");
            var client = await Client.GetClientAsync(_database, client_id, client_secret);
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
        [HttpGet("account/tokens")]
        public async Task<ActionResult> UserTokens([FromHeader] string client_id, [FromHeader] string client_secret)
        {
            if (!IsDBInitialized)
                return Problem("Драйвер базы данных не инициализирован");
            var client = await Client.GetClientAsync(_database, client_id, client_secret);
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
        #region Private Logic
        #endregion
    }
}
