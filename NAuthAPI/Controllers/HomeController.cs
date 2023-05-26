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
    }
}
