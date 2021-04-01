using ExampleApp.Identity;
using ExampleApp.Services;
using Microsoft.AspNetCore.Identity;
using Microsoft.AspNetCore.Mvc;
using Microsoft.AspNetCore.Mvc.RazorPages;
using System.Threading.Tasks;

namespace ExampleApp.Pages.Store {

    public class PasswordResetModel : PageModel {

        public PasswordResetModel(UserManager<AppUser> manager,
                ISMSSender sender) {
            UserManager = manager;
            SMSSender = sender;
        }

        public UserManager<AppUser> UserManager { get; set; }
        public ISMSSender SMSSender { get; set; }

        public async Task<IActionResult> OnPost(string email) {
            AppUser user = await UserManager.FindByEmailAsync(email);
            if (user != null) {
                string token =
                    await UserManager.GeneratePasswordResetTokenAsync(user);
                SMSSender.SendMessage(user, $"Your password reset token is {token}");
            }

            return RedirectToPage("PasswordResetConfirm", new { email = email });
        }
    }
}
