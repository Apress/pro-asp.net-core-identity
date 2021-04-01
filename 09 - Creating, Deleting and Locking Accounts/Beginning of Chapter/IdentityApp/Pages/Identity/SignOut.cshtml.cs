using Microsoft.AspNetCore.Identity;
using Microsoft.AspNetCore.Mvc;
using System.Threading.Tasks;
using Microsoft.AspNetCore.Authorization;

namespace IdentityApp.Pages.Identity {

    [AllowAnonymous]
    public class SignOutModel : UserPageModel {

        public SignOutModel(SignInManager<IdentityUser> signMgr)
            => SignInManager = signMgr;

        public SignInManager<IdentityUser> SignInManager { get; set; }

        public async Task<IActionResult> OnPostAsync() {
            await SignInManager.SignOutAsync();
            return RedirectToPage();
        }
    }
}
