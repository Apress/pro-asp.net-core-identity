using Microsoft.AspNetCore.Identity;
using Microsoft.AspNetCore.Mvc;

namespace IdentityApp.Pages.Identity.Admin {

    public class DeleteModel : AdminPageModel {

        public DeleteModel(UserManager<IdentityUser> mgr) => UserManager = mgr;

        public UserManager<IdentityUser> UserManager { get; set; }

        public IdentityUser IdentityUser { get; set; } = new();

        [BindProperty(SupportsGet = true)]
        public string? Id { get; set; }

        public async Task<IActionResult> OnGetAsync() {
            if (string.IsNullOrEmpty(Id)) {
                return RedirectToPage("Selectuser",
                    new { Label = "Delete", Callback = "Delete" });
            }
            IdentityUser = await UserManager.FindByIdAsync(Id);
            return Page();
        }

        public async Task<IActionResult> OnPostAsync() {
            IdentityUser = await UserManager.FindByIdAsync(Id);
            IdentityResult result = await UserManager.DeleteAsync(IdentityUser);
            if (result.Process(ModelState)) {
                return RedirectToPage("Dashboard");
            }
            return Page();
        }
    }
}
