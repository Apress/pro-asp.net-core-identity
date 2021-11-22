using Microsoft.AspNetCore.Mvc;

namespace ExampleApp.Controllers {

    public class HomeController : Controller {

        public IActionResult Test() => View();
    }
}
