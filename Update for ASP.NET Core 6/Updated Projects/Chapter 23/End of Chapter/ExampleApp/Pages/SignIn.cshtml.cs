using ExampleApp.Identity;
using Microsoft.AspNetCore.Identity;
using Microsoft.AspNetCore.Mvc;
using Microsoft.AspNetCore.Mvc.RazorPages;
using Microsoft.AspNetCore.Mvc.Rendering;
using SignInResult = Microsoft.AspNetCore.Identity.SignInResult;

namespace ExampleApp.Pages {
    public class SignInModel : PageModel {

        public SignInModel(UserManager<AppUser> userManager,
                SignInManager<AppUser> signInManager) {
            UserManager = userManager;
            SignInManager = signInManager;
        }

        public UserManager<AppUser> UserManager { get; set; }
        public SignInManager<AppUser> SignInManager { get; set; }

        public SelectList Users => new SelectList(
            UserManager.Users.OrderBy(u => u.EmailAddress),
                "EmailAddress", "EmailAddress");


        public string Username { get; set; } = String.Empty;

        public int? Code { get; set; }

        public string? Message { get; set; }

        public void OnGet(int? code) {
            if (code == StatusCodes.Status401Unauthorized) {
                Message = "401 - Challenge Response";
            } else if (code == StatusCodes.Status403Forbidden) {
                Message = "403 - Forbidden Response";
            }
            Username = User.Identity?.Name ?? "(No Signed In User)";
        }

        public async Task<IActionResult> OnPost(string username,
                [FromQuery] string returnUrl) {
            AppUser user = await UserManager.FindByEmailAsync(username);
            UserLoginInfo? loginInfo = user?.UserLogins?.FirstOrDefault();
            if (loginInfo != null) {
                return RedirectToPage("/ExternalSignIn", new {
                    returnUrl, providerName = loginInfo.LoginProvider
                });
            }
            return RedirectToPage("SignInPassword", new { username, returnUrl });
        }
    }
}
