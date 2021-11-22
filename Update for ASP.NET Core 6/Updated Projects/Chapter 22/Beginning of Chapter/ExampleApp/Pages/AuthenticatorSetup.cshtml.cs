using ExampleApp.Identity;
using Microsoft.AspNetCore.Identity;
using Microsoft.AspNetCore.Mvc;
using Microsoft.AspNetCore.Mvc.RazorPages;

namespace ExampleApp.Pages {

    public class AuthenticatorSetupModel : PageModel {

        public AuthenticatorSetupModel(UserManager<AppUser> userManager) =>
            UserManager = userManager;

        public UserManager<AppUser> UserManager { get; set; }

        [BindProperty(SupportsGet = true)]
        public string Id { get; set; } = String.Empty;

        public AppUser AppUser { get; set; } = new();

        public string AuthenticatorUrl { get; set; } = String.Empty;

        public async Task OnGetAsync() {
            AppUser = await UserManager.FindByIdAsync(Id);
            if (AppUser != null) {
                if (AppUser.AuthenticatorKey != null) {
                    AuthenticatorUrl =
                        $"otpauth://totp/ExampleApp:{AppUser.EmailAddress}"
                        + $"?secret={AppUser.AuthenticatorKey}";
                }
            }
        }

        public async Task<IActionResult> OnPostAsync(string task) {
            AppUser = await UserManager.FindByIdAsync(Id);
            if (AppUser != null) {
                switch (task) {
                    case "enable":
                        AppUser.AuthenticatorEnabled = true;
                        AppUser.TwoFactorEnabled = true;
                        break;
                    case "disable":
                        AppUser.AuthenticatorEnabled = false;
                        AppUser.TwoFactorEnabled = false;
                        break;
                    default:
                        await UserManager.ResetAuthenticatorKeyAsync(AppUser);
                        break;
                }
                await UserManager.UpdateAsync(AppUser);
            }
            return RedirectToPage();
        }
    }
}
