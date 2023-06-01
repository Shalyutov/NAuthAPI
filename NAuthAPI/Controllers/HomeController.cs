using Microsoft.AspNetCore.Mvc;

namespace NAuthAPI.Controllers
{
    [Route("/")]
    [ApiController]
    public class HomeController : ControllerBase
    {
        readonly private AppContext _db;
        public HomeController(AppContext db)
        {
            _db = db;
        }
        public IActionResult Index()
        {
            return Ok("NAuth Federation");
        }
        [HttpGet("version")]
        public IActionResult Version()
        {
            return Ok("0.0.3.0");
        }
        [HttpGet("db/status")]
        public ActionResult DatabaseStatus()
        {
            if (_db == null)
                return Problem("Драйвер базы данных не инициализирован");
            else
                return Ok("Драйвер базы данных успешно запущен");
        }
    }
}
