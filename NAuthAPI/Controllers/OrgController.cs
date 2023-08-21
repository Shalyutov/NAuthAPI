using Microsoft.AspNetCore.Authorization;
using Microsoft.AspNetCore.Mvc;

namespace NAuthAPI.Controllers
{
    [Authorize]
    [Route("org")]
    public class OrgController : ControllerBase
    {
        private readonly AppContext _database;
        public OrgController(AppContext db)
        {
            _database = db;
        }
        #region Endpoints Logic
        //TODO Clients
        /*[HttpPost("client")]
        public async Task<ActionResult> CreateClient([FromQuery] string client)
        {
            return NoContent();
        }
        [HttpDelete("client")]
        public async Task<ActionResult> DeleteClient([FromQuery] string client)
        {
            return NoContent();
        }
        [HttpPut("client")]
        public async Task<ActionResult> UpdateClient([FromQuery] string client)
        {
            return NoContent();
        }
        [HttpGet("client")]
        public async Task<ActionResult> GetClient([FromQuery] string client)
        {
            return NoContent();
        }*/
        #endregion
    }
}
