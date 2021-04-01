using Microsoft.AspNetCore.Identity;
using Microsoft.AspNetCore.Mvc;
using System.ComponentModel.DataAnnotations;
using System.Threading.Tasks;

namespace IdentityApp.Pages.Identity {

    public class PasswordChangeBindingTarget {
        [Required]
        public string Current { get; set; }

        [Required]
        public string NewPassword { get; set; }

        [Required]
        [Compare(nameof(NewPassword))]
        public string ConfirmPassword { get; set; }
    }

    public class UserPasswordChangeModel : UserPageModel {

        public UserPasswordChangeModel(UserManager<IdentityUser> usrMgr)
            => UserManager = usrMgr;

        public UserManager<IdentityUser> UserManager { get; set; }

        public async Task<IActionResult> OnPostAsync(
                PasswordChangeBindingTarget data) {
            if (ModelState.IsValid) {
                IdentityUser user = await UserManager.GetUserAsync(User);
                IdentityResult result = await UserManager.ChangePasswordAsync(user,
                    data.Current, data.NewPassword);
                if (result.Process(ModelState)) {
                    TempData["message"] = "Password changed";
                    return RedirectToPage();
                }
            }
            return Page();
        }
    }
}
