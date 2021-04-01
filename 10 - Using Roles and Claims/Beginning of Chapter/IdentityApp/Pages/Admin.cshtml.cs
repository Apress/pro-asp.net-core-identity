using IdentityApp.Models;
using Microsoft.AspNetCore.Mvc;
using Microsoft.AspNetCore.Mvc.RazorPages;
using Microsoft.AspNetCore.Authorization;

namespace IdentityApp.Pages {

    [Authorize(Roles = "Admin")]
    public class AdminModel : PageModel {

        public AdminModel(ProductDbContext ctx) => DbContext = ctx;

        public ProductDbContext DbContext { get; set; }

        public IActionResult OnPost(long id) {
            Product p = DbContext.Find<Product>(id);
            if (p != null) {
                DbContext.Remove(p);
                DbContext.SaveChanges();
            }
            return Page();
        }
    }
}
