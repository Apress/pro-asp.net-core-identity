using ExampleApp.Identity;
using ExampleApp.Services;
using Microsoft.AspNetCore.Identity;
using Microsoft.AspNetCore.Mvc;
using Microsoft.AspNetCore.Mvc.RazorPages;
using System.Threading.Tasks;
using SignInResult = Microsoft.AspNetCore.Identity.SignInResult;

namespace ExampleApp.Pages {

    public class SignInTwoFactorModel : PageModel {

        public SignInTwoFactorModel(UserManager<AppUser> userManager,
                      SignInManager<AppUser> signInManager,
                      ISMSSender sender) {
            UserManager = userManager;
            SignInManager = signInManager;
            SMSSender = sender;
        }

        public UserManager<AppUser> UserManager { get; set; }
        public SignInManager<AppUser> SignInManager { get; set; }
        public ISMSSender SMSSender { get; set; }

        public bool AuthenticatorEnabled { get; set; }

        public async Task OnGet() {
            AppUser user = await SignInManager.GetTwoFactorAuthenticationUserAsync();
            if (user != null) {
                AuthenticatorEnabled = user.AuthenticatorEnabled;
                if (!AuthenticatorEnabled) {
                    await UserManager.UpdateSecurityStampAsync(user);
                    string token = await UserManager.GenerateTwoFactorTokenAsync(
                        user, IdentityConstants.TwoFactorUserIdScheme);
                    SMSSender.SendMessage(user, $"Your security code is {token}");
                }
            }
        }

        public async Task<IActionResult> OnPost(string code, string rememberMe,
                [FromQuery] string returnUrl) {
            AppUser user = await SignInManager.GetTwoFactorAuthenticationUserAsync();
            if (user != null && !string.IsNullOrEmpty(code)) {
                SignInResult result = SignInResult.Failed;
                AuthenticatorEnabled = user.AuthenticatorEnabled;
                bool rememberClient = !string.IsNullOrEmpty(rememberMe);
                if (AuthenticatorEnabled) {
                    string authCode = code.Replace(" ", string.Empty);
                    result = await SignInManager.TwoFactorAuthenticatorSignInAsync(
                        authCode, false, rememberClient);
                } else {
                    result = await SignInManager.TwoFactorSignInAsync(
                        IdentityConstants.TwoFactorUserIdScheme, code,
                        true, rememberClient);
                }
                if (result.Succeeded) {
                    return Redirect(returnUrl ?? "/");
                } else if (result.IsLockedOut) {
                    ModelState.AddModelError("", "Locked out");
                } else if (result.IsNotAllowed) {
                    ModelState.AddModelError("", "Not allowed");
                } else {
                    ModelState.AddModelError("", "Authentication failed");
                }
            }
            return Page();
        }
    }
}
