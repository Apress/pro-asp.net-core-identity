using Microsoft.AspNetCore.Authorization;
using Microsoft.AspNetCore.Identity;
using Microsoft.AspNetCore.Mvc;
using Microsoft.AspNetCore.WebUtilities;
using System.Text;
using System.Threading.Tasks;

namespace IdentityApp.Pages.Identity {

    [AllowAnonymous]
    public class SignUpConfirmModel : UserPageModel {

        public SignUpConfirmModel(UserManager<IdentityUser> usrMgr)
            => UserManager = usrMgr;

        public UserManager<IdentityUser> UserManager { get; set; }

        [BindProperty(SupportsGet = true)]
        public string Email { get; set; }

        [BindProperty(SupportsGet = true)]
        public string Token { get; set; }

        public bool ShowConfirmedMessage { get; set; } = false;

        public async Task<IActionResult> OnGetAsync() {
            if (!string.IsNullOrEmpty(Email) && !string.IsNullOrEmpty(Token)) {
                IdentityUser user = await UserManager.FindByEmailAsync(Email);
                if (user != null) {
                    string decodedToken = Encoding.UTF8.GetString(
                        WebEncoders.Base64UrlDecode(Token));
                    IdentityResult result =
                        await UserManager.ConfirmEmailAsync(user, decodedToken);
                    if (result.Process(ModelState)) {
                        ShowConfirmedMessage = true;
                    }
                }
            }
            return Page();
        }
    }
}
