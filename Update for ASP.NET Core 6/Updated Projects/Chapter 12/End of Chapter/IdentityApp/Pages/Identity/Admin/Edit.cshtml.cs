using Microsoft.AspNetCore.Identity;
using Microsoft.AspNetCore.Mvc;
using System.ComponentModel.DataAnnotations;
using System.Threading.Tasks;

namespace IdentityApp.Pages.Identity.Admin {

    public class EditBindingTarget {
        [Required]
        public string Username { get; set; } = string.Empty;
        [Required]
        [EmailAddress]
        public string Email { get; set; } = string.Empty;
        [Phone]
        public string? PhoneNumber { get; set; }
    }

    public class EditModel : AdminPageModel {

        public EditModel(UserManager<IdentityUser> mgr) => UserManager = mgr;

        public UserManager<IdentityUser> UserManager { get; set; }

        public IdentityUser IdentityUser { get; set; } = new();

        [BindProperty(SupportsGet = true)]
        public string Id { get; set; } = string.Empty;

        public async Task<IActionResult> OnGetAsync() {
            if (string.IsNullOrEmpty(Id)) {
                return RedirectToPage("Selectuser",
                    new { Label = "Edit User", Callback = "Edit" });
            }
            IdentityUser = await UserManager.FindByIdAsync(Id);
            return Page();
        }

public async Task<IActionResult> OnPostAsync(
        [FromForm(Name = "IdentityUser")] EditBindingTarget userData) {
    if (!string.IsNullOrEmpty(Id) && ModelState.IsValid) {
        IdentityUser user = await UserManager.FindByIdAsync(Id);
        if (user != null) {
            user.UserName = userData.Email;
            user.Email = userData.Email;
            user.EmailConfirmed = true;
            if (!string.IsNullOrEmpty(userData.PhoneNumber)) {
                user.PhoneNumber = userData.PhoneNumber;
            }
            IdentityResult result = await UserManager.UpdateAsync(user);
            if (result.Process(ModelState)) {
                return RedirectToPage();
            }
        }
    }
    IdentityUser = await UserManager.FindByIdAsync(Id);
    return Page();
}
    }
}
