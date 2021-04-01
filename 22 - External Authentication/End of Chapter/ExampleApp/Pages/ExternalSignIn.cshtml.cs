using ExampleApp.Identity;
using Microsoft.AspNetCore.Authentication;
using Microsoft.AspNetCore.Identity;
using Microsoft.AspNetCore.Mvc;
using Microsoft.AspNetCore.Mvc.RazorPages;
using System.Linq;
using System.Security.Claims;
using System.Threading.Tasks;
using SignInResult = Microsoft.AspNetCore.Identity.SignInResult;

namespace ExampleApp.Pages {

    public class ExternalSignInModel : PageModel {

        public ExternalSignInModel(SignInManager<AppUser> signInManager,
                UserManager<AppUser> userManager) {
            SignInManager = signInManager;
            UserManager = userManager;
        }

        public SignInManager<AppUser> SignInManager { get; set; }
        public UserManager<AppUser> UserManager { get; set; }

        public string ProviderDisplayName { get; set; }

        public IActionResult OnPost(string providerName,
                string returnUrl = "/") {

            string redirectUrl = Url.Page("./ExternalSignIn",
                 pageHandler: "Correlate", values: new { returnUrl });
            AuthenticationProperties properties = SignInManager
              .ConfigureExternalAuthenticationProperties(providerName,
                  redirectUrl);
            return new ChallengeResult(providerName, properties);
        }

        public async Task<IActionResult> OnGetCorrelate(string returnUrl) {
            ExternalLoginInfo info = await SignInManager.GetExternalLoginInfoAsync();
            AppUser user = await UserManager.FindByLoginAsync(info.LoginProvider,
                info.ProviderKey);
            if (user == null) {
                string externalEmail =
                    info.Principal.FindFirst(ClaimTypes.Email)?.Value
                        ?? string.Empty;
                user = await UserManager.FindByEmailAsync(externalEmail);
                if (user == null) {
                    return RedirectToPage("/ExternalAccountConfirm",
                        new { returnUrl });
                } else {
                    await UserManager.AddLoginAsync(user, info);
                }
            }
            SignInResult result = await SignInManager.ExternalLoginSignInAsync(
                 info.LoginProvider, info.ProviderKey, false, false);
            if (result.Succeeded) {
                return RedirectToPage("ExternalSignIn", "Confirm",
                    new { info.ProviderDisplayName, returnUrl });
            } else if (result.RequiresTwoFactor) {
                string postSignInUrl = this.Url.Page("/ExternalSignIn", "Confirm",
                    new { info.ProviderDisplayName, returnUrl });
                return RedirectToPage("/SignInTwoFactor",
                    new { returnUrl = postSignInUrl });
            }
            return RedirectToPage(new { error = true, returnUrl });
        }

        public async Task OnGetConfirmAsync() {
            string provider = User.FindFirstValue(ClaimTypes.AuthenticationMethod);
            ProviderDisplayName =
                (await SignInManager.GetExternalAuthenticationSchemesAsync())
                   .FirstOrDefault(s => s.Name == provider)?.DisplayName ?? provider;
        }
    }
}
