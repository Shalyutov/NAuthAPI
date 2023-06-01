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
        [HttpPut("account/update")]
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
