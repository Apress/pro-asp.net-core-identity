using IdentityApp.Models;
using Microsoft.AspNetCore.Mvc.RazorPages;

namespace IdentityApp.Pages {
    public class LandingModel : PageModel {

        public LandingModel(ProductDbContext ctx) => DbContext = ctx;

        public ProductDbContext DbContext { get; set; }

    }
}
