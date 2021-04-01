using Microsoft.AspNetCore.Identity;
using Microsoft.AspNetCore.Mvc;
using System.ComponentModel.DataAnnotations;
using System.Threading.Tasks;
using System.Linq;
using System.Text.RegularExpressions;

namespace IdentityApp.Pages.Identity {

    public class UserTwoFactorSetupModel : UserPageModel {

        public UserTwoFactorSetupModel(UserManager<IdentityUser> usrMgr,
              SignInManager<IdentityUser> signMgr) {
            UserManager = usrMgr;
            SignInManager = signMgr;
        }

        public UserManager<IdentityUser> UserManager { get; set; }
        public SignInManager<IdentityUser> SignInManager { get; set; }

        public IdentityUser IdentityUser { get; set; }

        public string AuthenticatorKey { get; set; }

        public string QrCodeUrl { get; set; }

        public async Task<IActionResult> OnGet() {
            await LoadAuthenticatorKeys();
            if (await UserManager.GetTwoFactorEnabledAsync(IdentityUser)) {
                return RedirectToPage("UserTwoFactorManage");
            }
            return Page();
        }

        public async Task<IActionResult> OnPostConfirm([Required] string confirm) {
            await LoadAuthenticatorKeys();
            if (ModelState.IsValid) {
                string token = Regex.Replace(confirm, @"\s", "");
                bool codeValid = await
                        UserManager.VerifyTwoFactorTokenAsync(IdentityUser,
                    UserManager.Options.Tokens.AuthenticatorTokenProvider, token);
                if (codeValid) {
                    TempData["RecoveryCodes"] = await UserManager
                        .GenerateNewTwoFactorRecoveryCodesAsync(IdentityUser, 10);
                    await UserManager.SetTwoFactorEnabledAsync(IdentityUser, true);
                    await SignInManager.RefreshSignInAsync(IdentityUser);
                    return RedirectToPage("UserRecoveryCodes");
                } else {
                    ModelState.AddModelError(string.Empty,
                        "Confirmation code invalid");
                }
            }
            return Page();
        }

        private async Task LoadAuthenticatorKeys() {
            IdentityUser = await UserManager.GetUserAsync(User);
            AuthenticatorKey =
                await UserManager.GetAuthenticatorKeyAsync(IdentityUser);
            if (AuthenticatorKey == null) {
                await UserManager.ResetAuthenticatorKeyAsync(IdentityUser);
                AuthenticatorKey =
                    await UserManager.GetAuthenticatorKeyAsync(IdentityUser);
                await SignInManager.RefreshSignInAsync(IdentityUser);
            }
            QrCodeUrl = $"otpauth://totp/ExampleApp:{IdentityUser.Email}"
                        + $"?secret={AuthenticatorKey}";
        }
    }
}
