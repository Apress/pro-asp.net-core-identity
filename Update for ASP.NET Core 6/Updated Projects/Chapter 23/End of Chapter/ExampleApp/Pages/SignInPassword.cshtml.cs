using ExampleApp.Identity;
using Microsoft.AspNetCore.Identity;
using Microsoft.AspNetCore.Mvc;
using Microsoft.AspNetCore.Mvc.RazorPages;
using SignInResult = Microsoft.AspNetCore.Identity.SignInResult;

namespace ExampleApp.Pages {

    public class SignInPasswordModel : PageModel {

        public SignInPasswordModel(UserManager<AppUser> userManager,
                SignInManager<AppUser> signInManager) {
            UserManager = userManager;
            SignInManager = signInManager;
        }

        public UserManager<AppUser> UserManager { get; set; }
        public SignInManager<AppUser> SignInManager { get; set; }

        public string? Username { get; set; }
        public string? ReturnUrl { get; set; }

        public void OnGet(string username, string returnUrl) {
            Username = username;
            ReturnUrl = returnUrl;
        }

        public async Task<ActionResult> OnPost(string username,
                string password, string returnUrl) {
            SignInResult result = SignInResult.Failed;
            AppUser user = await UserManager.FindByEmailAsync(username);
            if (user != null && !string.IsNullOrEmpty(password)) {
                result = await SignInManager.PasswordSignInAsync(user, password,
                    false, true);
            }
            if (!result.Succeeded) {
                if (result.IsLockedOut && user != null) {
                    TimeSpan remaining = (await UserManager
                        .GetLockoutEndDateAsync(user))
                        .GetValueOrDefault().Subtract(DateTimeOffset.Now);
                    ModelState.AddModelError("",
                        $"Locked Out for {remaining.Minutes} mins and"
                            + $" {remaining.Seconds} secs");
                } else if (result.RequiresTwoFactor) {
                    return RedirectToPage("/SignInTwoFactor", new { returnUrl });
                } else if (result.IsNotAllowed) {
                    ModelState.AddModelError("", "Sign In Not Allowed");
                } else {
                    ModelState.AddModelError("", "Access Denied");
                }
                Username = username;
                ReturnUrl = returnUrl;
                return Page();
            }
            return Redirect(returnUrl ?? "/signin");
        }
    }
}
