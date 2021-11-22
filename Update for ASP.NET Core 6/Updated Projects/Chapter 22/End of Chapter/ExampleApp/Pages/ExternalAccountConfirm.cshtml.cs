using ExampleApp.Identity;
using Microsoft.AspNetCore.Identity;
using Microsoft.AspNetCore.Mvc;
using Microsoft.AspNetCore.Mvc.RazorPages;
using System.Security.Claims;
using System.Threading.Tasks;

namespace ExampleApp.Pages {

    public class ExternalAccountConfirmModel : PageModel {

        public ExternalAccountConfirmModel(UserManager<AppUser> userManager,
                SignInManager<AppUser> signInManager) {
            UserManager = userManager;
            SignInManager = signInManager;
        }

        public UserManager<AppUser> UserManager { get; set; }
        public SignInManager<AppUser> SignInManager { get; set; }

        public AppUser AppUser { get; set; } = new AppUser();

        public string? ProviderDisplayName { get; set; }

        [BindProperty(SupportsGet = true)]
        public string ReturnUrl { get; set; } = "/";

        public async Task<IActionResult> OnGetAsync() {
            ExternalLoginInfo info = await SignInManager.GetExternalLoginInfoAsync();
            if (info == null) {
                return Redirect(ReturnUrl);
            } else {
                ClaimsPrincipal external = info.Principal;
                AppUser.EmailAddress = external.FindFirstValue(ClaimTypes.Email);
                AppUser.UserName = external.FindFirstValue(ClaimTypes.Name);
                ProviderDisplayName = info.ProviderDisplayName;
                return Page();
            }
        }

        public async Task<IActionResult> OnPostAsync(string username) {
            ExternalLoginInfo info = await SignInManager.GetExternalLoginInfoAsync();

            if (info != null) {
                ClaimsPrincipal external = info.Principal;
                AppUser.UserName = username;
                AppUser.EmailAddress = external.FindFirstValue(ClaimTypes.Email);
                AppUser.EmailAddressConfirmed = true;
                IdentityResult result = await UserManager.CreateAsync(AppUser);
                if (result.Succeeded) {
                    await UserManager.AddClaimAsync(AppUser,
                        new Claim(ClaimTypes.Role, "User"));
                    await UserManager.AddLoginAsync(AppUser, info);
                    await SignInManager.ExternalLoginSignInAsync(info.LoginProvider,
                        info.ProviderKey, false);
                    return Redirect(ReturnUrl);
                } else {
                    foreach (IdentityError err in result.Errors) {
                        ModelState.AddModelError(string.Empty, err.Description);
                    }
                }
            } else {
                ModelState.AddModelError(string.Empty, "No external login found");
            }
            return Page();
        }
    }
}
