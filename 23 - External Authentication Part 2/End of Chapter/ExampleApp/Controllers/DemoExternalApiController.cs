using Microsoft.AspNetCore.Mvc;
using System.Collections.Generic;

namespace ExampleApp.Controllers {

    [ApiController]
    [Route("api/[controller]")]
    public class DemoExternalApiController : Controller {

        private Dictionary<string, string> data
            = new Dictionary<string, string> {
                { "token1", "This is Alice's external data" },
                { "token2", "This is Dora's external data" },
            };

        [HttpGet]
        public IActionResult GetData([FromHeader] string authorization) {
            if (!string.IsNullOrEmpty(authorization)) {
                string token = authorization?[7..];
                if (!string.IsNullOrEmpty(token) && data.ContainsKey(token)) {
                    return Json(new { data = data[token] });
                }
            }
            return NotFound();
        }
    }
}
