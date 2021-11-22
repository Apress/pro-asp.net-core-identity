using ExampleApp.Identity;
using Microsoft.AspNetCore.Identity;
using Microsoft.AspNetCore.Mvc;
using Microsoft.AspNetCore.Mvc.RazorPages;
using System.Threading.Tasks;

namespace ExampleApp.Pages.Store {

    public class UsersModel : PageModel {

        public UsersModel(UserManager<AppUser> userMgr) => UserManager = userMgr;

        public UserManager<AppUser> UserManager { get; set; }

        public AppUser AppUserObject { get; set; } = new AppUser();

        public async Task OnGetAsync(string? id) {
            if (id != null) {
                AppUserObject = await UserManager.FindByIdAsync(id) ?? new AppUser();
            }
        }

        public async Task<IActionResult> OnPost(AppUser user, string newPassword) {
            IdentityResult result = IdentityResult.Success;
            AppUser storeUser = await UserManager.FindByIdAsync(user.Id);

            if (storeUser == null) {
                if (string.IsNullOrEmpty(newPassword)) {
                    ModelState.AddModelError("", "Password Required");
                    return Page();
                }
                result = await UserManager.CreateAsync(user, newPassword);
            } else {
                storeUser.UpdateFrom(user, out bool changed);
                if (newPassword != null) {
                    if (await UserManager.HasPasswordAsync(storeUser)) {
                        await UserManager.RemovePasswordAsync(storeUser);
                    }
                    result = await UserManager.AddPasswordAsync(storeUser, newPassword);
                }
                if (changed && UserManager.SupportsUserSecurityStamp) {
                    await UserManager.UpdateSecurityStampAsync(storeUser);
                }
                if (result.Succeeded) {
                    result = await UserManager.UpdateAsync(storeUser);
                }
            }
            if (result.Succeeded) {
                return RedirectToPage("users", new { searchname = user.Id });
            } else {
                foreach (IdentityError err in result.Errors) {
                    Console.WriteLine(">>>> " + err);
                    ModelState.AddModelError("", err.Description ?? "Error");
                }
                AppUserObject = user;
                return Page();
            }
        }
    }
}
