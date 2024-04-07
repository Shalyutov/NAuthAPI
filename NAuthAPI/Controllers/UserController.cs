﻿using Microsoft.AspNetCore.Authentication;
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
    public class UserController(AppContext db, IKVEngine kvService) : ControllerBase
    {
        readonly IKVEngine _kvService = kvService;

        #region Endpoints Logic

        [Client]
        [HttpGet("account")]
        public async Task<ActionResult> GetAccount()
        {
            string id = HttpContext.User.FindFirst(ClaimTypes.SerialNumber)?.Value ?? "";
            string scope = HttpContext.User.FindFirst("scope")?.Value ?? "";
            User? user = await db.GetUser(id);
            if (user != null)
            {
                Dictionary<string, object> claims = [];
                foreach (var claim in ScopeHelper.Scopes)
                {
                    if (!string.IsNullOrEmpty(claim))
                    {
                        string? value = claim switch
                        {
                            "lastname" => user.LastName,
                            "surname" => user.Surname,
                            "name" => user.Name,
                            ClaimTypes.Email => "email",
                            ClaimTypes.MobilePhone => "phone",
                            ClaimTypes.Gender => "gender",
                            ClaimTypes.SerialNumber => "guid",
                            _ => null
                        };
                        if (scope.Contains("user") ||
                            scope.Contains($"user:{claim}") ||
                            scope.Contains($"user:{claim}:get"))
                        {
                            if (!string.IsNullOrEmpty(value))
                            {
                                claims.Add(claim, value);
                            }
                        }
                    }
                    
                }
                return Ok(claims);
            }
            else
            {
                return NoContent();
            }
        }
        [Client]
        [HttpGet("claims")]
        public async Task<ActionResult> GetClaims([FromForm] string scopes)
        {
            string id = HttpContext.User.FindFirst(ClaimTypes.SerialNumber)?.Value ?? "";
            var validScopes = (HttpContext.User.FindFirst("scope")?.Value ?? "").Split(" ");
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
        [Client]
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

            if (await db.DeleteAccount(id))
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
