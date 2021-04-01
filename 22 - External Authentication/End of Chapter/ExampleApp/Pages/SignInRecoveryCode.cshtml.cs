using ExampleApp.Identity;
using Microsoft.AspNetCore.Identity;
using Microsoft.AspNetCore.Mvc;
using Microsoft.AspNetCore.Mvc.RazorPages;
using System.Threading.Tasks;
using SignInResult = Microsoft.AspNetCore.Identity.SignInResult;

namespace ExampleApp.Pages {

    public class SignInRecoveryCodeModel : PageModel {

        public SignInRecoveryCodeModel(SignInManager<AppUser> manager)
            => SignInManager = manager;

        public SignInManager<AppUser> SignInManager { get; set; }

        public async Task<IActionResult> OnPostAsync(string code,
                string returnUrl) {
            if (string.IsNullOrEmpty(code)) {
                ModelState.AddModelError("", "Code required");
            } else {
                SignInResult result =
                    await SignInManager.TwoFactorRecoveryCodeSignInAsync(code);
                if (result.Succeeded) {
                    return Redirect(returnUrl ?? "/");
                } else {
                    ModelState.AddModelError("", "Sign In Failed");
                }
            }
            return Page();
        }
    }
}
