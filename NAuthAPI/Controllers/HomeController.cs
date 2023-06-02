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
            return Ok("0.0.3.9");
        }
        [HttpGet("health")]
        public ActionResult DatabaseStatus()
        {
            if (_db == null)
                return Problem("������� ���� ������ �� ���������������");
            else
                return Ok("������� ���� ������ ������� �������");
        }
    }
}
