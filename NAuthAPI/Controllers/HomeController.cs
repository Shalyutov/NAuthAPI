using Microsoft.AspNetCore.Mvc;

namespace NAuthAPI.Controllers
{
    [Route("/")]
    [ApiController]
    public class HomeController : ControllerBase
    {
        public IActionResult Index()
        {
            return Ok("NAuth Federation");
        }
        [HttpGet("version")]
        public IActionResult Version()
        {
            return Ok("0.0.2.3");
        }
    }
}
