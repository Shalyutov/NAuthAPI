using Microsoft.AspNetCore.Mvc;

namespace NAuthAPI.Controllers
{
    [Route("/")]
    [ApiController]
    public class HomeController(AppContext db) : ControllerBase
    {
        public IActionResult Index()
        {
            return Ok("NAuth Federation");
        }
        [HttpGet("version")]
        public IActionResult Version()
        {
            return Ok("0.2.0");
        }
        [HttpGet("health")]
        public ActionResult DatabaseStatus()
        {
            if (db == null)
                return Problem("Драйвер базы данных не инициализирован");
            else
                return Ok("Драйвер базы данных успешно запущен");
        }
    }
}
