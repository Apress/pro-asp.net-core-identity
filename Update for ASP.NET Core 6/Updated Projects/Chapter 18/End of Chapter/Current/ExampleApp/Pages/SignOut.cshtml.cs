using Microsoft.AspNetCore.Authentication;
using Microsoft.AspNetCore.Mvc;
using Microsoft.AspNetCore.Mvc.RazorPages;

namespace ExampleApp.Pages {
    public class SignOutModel : PageModel {
        public string Username { get; set; } = String.Empty;

        public void OnGet() {
            Username = User.Identity?.Name ?? "(No Signed In User)";
        }

        public async Task<ActionResult> OnPost() {
            await HttpContext.SignOutAsync();
            return RedirectToPage("SignIn");
        }
    }
}
