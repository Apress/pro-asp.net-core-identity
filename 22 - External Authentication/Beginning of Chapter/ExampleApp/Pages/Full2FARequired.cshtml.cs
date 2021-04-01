using ExampleApp.Identity;
using Microsoft.AspNetCore.Authentication;
using Microsoft.AspNetCore.Identity;
using Microsoft.AspNetCore.Mvc;
using Microsoft.AspNetCore.Mvc.RazorPages;
using System.Threading.Tasks;

namespace ExampleApp.Pages {

    public class Full2FARequiredModel : PageModel {

        public Full2FARequiredModel(UserManager<AppUser> userManager,
                SignInManager<AppUser> signInManager) {
            UserManager = userManager;
            SignInManager = signInManager;
        }

        public UserManager<AppUser> UserManager { get; set; }
        public SignInManager<AppUser> SignInManager { get; set; }

        public async Task<IActionResult> OnPostAsync(string returnUrl) {
            AppUser user = await UserManager.GetUserAsync(HttpContext.User);
            if (await SignInManager.IsTwoFactorClientRememberedAsync(user)) {
                await SignInManager.ForgetTwoFactorClientAsync();
            }
            await HttpContext.SignOutAsync();
            return Redirect($"/signin?returnUrl={returnUrl}");
        }
    }
}
