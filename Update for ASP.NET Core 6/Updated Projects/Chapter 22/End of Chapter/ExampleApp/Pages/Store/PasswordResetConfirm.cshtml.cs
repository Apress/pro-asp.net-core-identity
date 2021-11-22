using System;
using System.Collections.Generic;
using System.Linq;
using System.Threading.Tasks;
using ExampleApp.Identity;
using Microsoft.AspNetCore.Identity;
using Microsoft.AspNetCore.Mvc;
using Microsoft.AspNetCore.Mvc.RazorPages;

namespace ExampleApp.Pages.Store {

    public class PasswordResetConfirmModel : PageModel {

        public PasswordResetConfirmModel(UserManager<AppUser> manager)
            => UserManager = manager;

        public UserManager<AppUser> UserManager { get; set; }

        [BindProperty(SupportsGet = true)]
        public string Email { get; set; } = String.Empty;

        [BindProperty(SupportsGet = true)]
        public bool Changed { get; set; } = false;

        public async Task<IActionResult> OnPostAsync(string password, string token) {
            AppUser user = await UserManager.FindByEmailAsync(Email);
            if (user != null) {
                IdentityResult result = await UserManager.ResetPasswordAsync(user,
                    token, password);
                if (result.Succeeded) {
                    return RedirectToPage(new { Changed = true });
                } else {
                    foreach (IdentityError err in result.Errors) {
                        ModelState.AddModelError("", err.Description);
                    }
                }
            } else {
                ModelState.AddModelError("", "Password Change Error");
            }
            return Page();
        }
    }
}
