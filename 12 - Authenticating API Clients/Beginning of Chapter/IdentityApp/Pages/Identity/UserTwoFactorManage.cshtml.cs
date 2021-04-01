using Microsoft.AspNetCore.Identity;
using Microsoft.AspNetCore.Mvc;
using System.Threading.Tasks;

namespace IdentityApp.Pages.Identity {

    public class UserTwoFactorManageModel : UserPageModel {

        public UserTwoFactorManageModel(UserManager<IdentityUser> usrMgr,
                SignInManager<IdentityUser> signMgr) {
            UserManager = usrMgr;
            SignInManager = signMgr;
        }

        public UserManager<IdentityUser> UserManager { get; set; }
        public SignInManager<IdentityUser> SignInManager { get; set; }

        public IdentityUser IdentityUser { get; set; }


        public async Task<bool> IsTwoFactorEnabled()
            => await UserManager.GetTwoFactorEnabledAsync(IdentityUser);

        public async Task OnGetAsync() {
            IdentityUser = await UserManager.GetUserAsync(User);
        }

        public async Task<IActionResult> OnPostDisable() {
            IdentityUser = await UserManager.GetUserAsync(User);
            IdentityResult result = await
                UserManager.SetTwoFactorEnabledAsync(IdentityUser, false);
            if (result.Process(ModelState)) {
                await SignInManager.SignOutAsync();
                return RedirectToPage("Index", new { });
            }
            return Page();
        }

        public async Task<IActionResult> OnPostGenerateCodes() {
            IdentityUser = await UserManager.GetUserAsync(User);
            TempData["RecoveryCodes"] =
                await UserManager.GenerateNewTwoFactorRecoveryCodesAsync(
                    IdentityUser, 10);
            return RedirectToPage("UserRecoveryCodes");
        }
    }
}
