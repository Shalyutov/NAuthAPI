using Microsoft.AspNetCore.Authentication;
using Microsoft.AspNetCore.Authorization;
using Microsoft.AspNetCore.Http;
using Microsoft.AspNetCore.Mvc;
using System.Reflection.Metadata.Ecma335;
using System.Security.Claims;

namespace NAuthAPI.Controllers
{
    [Authorize]
    [Route("user")]
    [ApiController]
    public class UserController(IAppContext db, IKVEngine kvService) : ControllerBase
    {
        readonly IKVEngine _kvService = kvService;

        #region Endpoints Logic

        [Client]
        [HttpGet("account")]
        public async Task<ActionResult> GetAccount()
        {
            string id = HttpContext.User.FindFirst(ClaimTypes.SerialNumber)?.Value ?? throw new Exception("Нет идентификатора пользователя");
            string? scope = HttpContext.User.FindFirst("scope")?.Value;
            if (string.IsNullOrEmpty(scope))
            {
                return NoContent();
            }

            User? user = await db.GetUser(id);
            if (user == null)
            {
                return NoContent();
            }
            if (scope == "user")
            {
                return Ok(new
                {
                    id,
                    surname = user.Surname,
                    name = user.Name,
                    lastname = user.LastName,
                    email = user.Email,
                    phone = user.Phone,
                    gender = user.Gender,
                });
            }
            Dictionary<string, object> claims = [];
            foreach (var claim in scope.Split(" "))//rethink
            {
                if (string.IsNullOrEmpty(claim))
                {
                    continue;
                }
                object? value = claim switch
                {
                    "surname" => user.Surname,
                    "name" => user.Name,
                    "lastname" => user.LastName,
                    "email" => user.Email,
                    "phone" => user.Phone,
                    "gender" => user.Gender,
                    "id" => id,
                    _ => null
                };
                if (scope.Contains($"user:{claim}") || scope.Contains($"user:{claim}:get"))
                {
                    if (value != null)
                    {
                        claims.Add(claim, value);
                    }
                }
            }
            return Ok(claims);
        }
        [Client]
        [HttpGet("claims")]
        public async Task<ActionResult> GetClaims([FromQuery] string scopes)
        {
            string id = HttpContext.User.FindFirstValue(ClaimTypes.SerialNumber) ?? throw new Exception("Нет идентификатора пользователя");
            var validScopes = (HttpContext.User.FindFirstValue("scope") ?? "").Split(" ");
            var requiredScopes = scopes.Split(" ");

            var data = await db.GetClaims(validScopes.Intersect(requiredScopes), id);
            if (data.Count > 0)
            {
                return Ok(data);
            }
            else
            {
                return NoContent();
            }
        }
        [TrustClient]
        [HttpPut("account")]
        public async Task<ActionResult> UpdateAccount()
        {
            if (!HttpContext.Request.HasFormContentType)
            {
                return BadRequest("Запрос не представляет форму для измененния данных");
            }
                
            var auth = await HttpContext.AuthenticateAsync();
            var scope = auth.Ticket?.Principal?.FindFirstValue("scope") ?? string.Empty;
            if (!scope.Contains("user"))
            {
                return BadRequest("Полученный токен не предназначен для доступа к этому ресурсу");
            }
                
            var form = await HttpContext.Request.ReadFormAsync();
            var user = HttpContext.User.FindFirst(ClaimTypes.SerialNumber)?.Value;
            if (user != null)
            {
                Dictionary<string, string> claims = [];
                foreach (var item in form) claims.Add(item.Key, item.Value.First() ?? "");

                var result = await db.UpdateUser(user, claims);
                if (result)
                {
                    return Ok();
                }
                else
                {
                    return BadRequest("Не удалось изменить атрибуты пользователя. Запрос к БД не выполнен");
                }
            }
            else
            {
                return BadRequest("Авторизованный ключ не содержит идентификатора учётной записи пользователя");
            }
        }
        [TrustClient]
        [HttpDelete("account")]
        public async Task<ActionResult> DeleteUser()
        {
            var scope = HttpContext.User.FindFirstValue("scope") ?? string.Empty;
            if (!scope.Contains("user"))
            {
                return BadRequest("Полученный токен не предназначен для доступа к этому ресурсу");
            }
                
            var id = HttpContext.User.FindFirst(ClaimTypes.SerialNumber)?.Value ?? "";
            
            var keys = await db.GetUserKeys(id);
            foreach (var key in keys)
                _kvService.DeleteKey(key);
            await db.DeleteUserAuthKeys(id);
            foreach (string item in "user sign reset delete".Split(" "))
            {
                await db.DeleteAccept(id, (HttpContext.Items["client"] as Client)?.Name ?? "", item);
            }

            if (await db.DeleteIdentity(id))
            {
                return Ok();
            }
            else
            {
                return Problem("Не удалось удалить учётную запись");
            }
        }
        [Client]
        [AllowAnonymous]
        [HttpGet("account/exists")]
        public async Task<ActionResult> IsUserExists([FromQuery] string username)
        {
            bool? exist = await db.IsUsernameExists(username);
            if (exist == null)
            {
                return NoContent();
            }
            else
            {
                return Ok(exist);
            }
        }
        [TrustClient]
        [HttpGet("account/tokens")]
        public async Task<ActionResult> UserTokens()
        {
            string user = HttpContext.User.FindFirstValue(ClaimTypes.SerialNumber) ?? "";
            var keys = await db.GetUserKeys(user);
            return Ok(keys);
        }

        #endregion

        #region Private Logic
        #endregion
    }
}
