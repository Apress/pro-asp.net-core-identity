using System.Threading.Tasks;
using ExampleApp.Identity;
using Microsoft.AspNetCore.Identity;
using Microsoft.AspNetCore.Mvc;
using Microsoft.AspNetCore.Mvc.RazorPages;

namespace ExampleApp.Pages.Store {
    public class PasswordChangeModel : PageModel {

        public PasswordChangeModel(UserManager<AppUser> manager) =>
            UserManager = manager;

        public UserManager<AppUser> UserManager { get; set; }

        [BindProperty(SupportsGet = true)]
        public bool Success { get; set; } = false;

        public async Task<IActionResult> OnPost(string oldPassword,
                string newPassword) {
            string? username = HttpContext.User.Identity?.Name;
            if (username != null) {
                AppUser user = await UserManager.FindByNameAsync(username);
                if (user != null && !string.IsNullOrEmpty(oldPassword)
                        && !string.IsNullOrEmpty(newPassword)) {
                    IdentityResult result = await UserManager.ChangePasswordAsync(
                        user, oldPassword, newPassword);
                    if (result.Succeeded) {
                        Success = true;
                    } else {
                        foreach (IdentityError err in result.Errors) {
                            ModelState.AddModelError("", err.Description);
                        }
                    }
                }
            }
            return Page();
        }
    }
}
