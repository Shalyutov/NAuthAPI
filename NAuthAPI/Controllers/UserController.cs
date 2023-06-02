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
        private bool IsDBInitialized => _database != null;
        public UserController(AppContext db)
        {
            _database = db;
        }
        #region Endpoints Logic
        [HttpGet("account")]
        public async Task<ActionResult> GetAccount([FromHeader] string client_id, [FromHeader] string client_secret)
        {
            if (!IsDBInitialized)
                return Problem("Драйвер базы данных не инициализирован");
            var client = await Client.GetClientAsync(_database, client_id, client_secret);
            if (client == null)
                return BadRequest("Клиентское приложение не авторизовано");
            try
            {
                Account? account = await _database.GetAccount(HttpContext.User.FindFirst(ClaimTypes.Upn)?.Value ?? "");
                if (account != null)
                {
                    Dictionary<string, string> claims = new();
                    foreach(var claim in account.Identity.Claims)
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
                        claims.Add(type, claim.Value);
                    }
                    return Ok(claims);
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
        public async Task<ActionResult> DeleteUser([FromHeader] string client_id, [FromHeader] string client_secret)
        {
            if (!IsDBInitialized)
                return Problem("Драйвер базы данных не инициализирован");
            var client = await Client.GetClientAsync(_database, client_id, client_secret);
            if (client == null)
                return BadRequest("Клиентское приложение не авторизовано");
            var auth = await HttpContext.AuthenticateAsync();
            var scope = auth.Ticket?.Principal?.FindFirstValue("scope") ?? string.Empty;
            if (!scope.Contains("user")) 
                return BadRequest("Полученный токен не предназначен для доступа к этому ресурсу");
            var guid = HttpContext.User.FindFirst(ClaimTypes.SerialNumber)?.Value ?? "";
            var delete_result = await _database.DeleteAccount(guid);
            var keys = await _database.GetUserKeys(guid);
            foreach (var key in keys) CryptoIO.DeleteSecurityKey(key);
            await _database.DeleteUserAuthKeys(guid);
            if (delete_result)
                return Ok();
            else
                return Problem("Не удалось удалить учётную запись");
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
