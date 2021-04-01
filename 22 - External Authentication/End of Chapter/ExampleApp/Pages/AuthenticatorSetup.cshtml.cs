using ExampleApp.Identity;
using Microsoft.AspNetCore.Identity;
using Microsoft.AspNetCore.Mvc;
using Microsoft.AspNetCore.Mvc.RazorPages;
using System.Threading.Tasks;

namespace ExampleApp.Pages {

    public class AuthenticatorSetupModel : PageModel {

        public AuthenticatorSetupModel(UserManager<AppUser> userManager) =>
            UserManager = userManager;

        public UserManager<AppUser> UserManager { get; set; }

        [BindProperty(SupportsGet = true)]
        public string Id { get; set; }

        public AppUser AppUser { get; set; }

        public string AuthenticatorUrl { get; set; }

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
