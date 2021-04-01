using IdentityApp.Models;
using Microsoft.AspNetCore.Mvc;
using Microsoft.AspNetCore.Authorization;

namespace IdentityApp.Controllers {

    [Authorize(Roles = "Admin")]
    public class AdminController : Controller {
        private ProductDbContext DbContext;

        public AdminController(ProductDbContext ctx) => DbContext = ctx;

        public IActionResult Index() => View(DbContext.Products);

        [HttpGet]
        public IActionResult Create() => View("Edit", new Product());

        [HttpGet]
        public IActionResult Edit(long id) {
            Product p = DbContext.Find<Product>(id);
            if (p != null) {
                return View("Edit", p);
            }
            return RedirectToAction(nameof(Index));
        }

        [HttpPost]
        public IActionResult Save(Product p) {
            DbContext.Update(p);
            DbContext.SaveChanges();
            return RedirectToAction(nameof(Index));
        }

        [HttpPost]
        public IActionResult Delete(long id) {
            Product p = DbContext.Find<Product>(id);
            if (p != null) {
                DbContext.Remove(p);
                DbContext.SaveChanges();
            }
            return RedirectToAction(nameof(Index));
        }
    }
}
