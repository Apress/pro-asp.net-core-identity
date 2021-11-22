using ExampleApp.Identity;
using Microsoft.AspNetCore.Identity;
using Microsoft.AspNetCore.Mvc;
using Microsoft.AspNetCore.Mvc.RazorPages;
using System.Collections.Generic;
using System.Linq;
using System.Threading.Tasks;

namespace ExampleApp.Pages.Store {

    public class RolesModel : PageModel {

        public RolesModel(UserManager<AppUser> userManager,
                RoleManager<AppRole> roleManager) {
            UserManager = userManager;
            RoleManager = roleManager;
        }

        public UserManager<AppUser> UserManager { get; set; }
        public RoleManager<AppRole> RoleManager { get; set; }

        public IEnumerable<AppRole> Roles => RoleManager.Roles.OrderBy(r => r.Name);

        public async Task<IList<AppUser>> GetUsersInRole(AppRole role) =>
            await UserManager.GetUsersInRoleAsync(role.Name);

        public async Task<IActionResult> OnPostDelete(string id) {
            AppRole role = await RoleManager.FindByIdAsync(id);
            if (role != null) {
                IdentityResult result = await RoleManager.DeleteAsync(role);
                if (!result.Succeeded) {
                    return ProcessErrors(result.Errors);
                }
            }
            return RedirectToPage();
        }

        public async Task<IActionResult> OnPostSave(AppRole editedRole) {
            IdentityResult result = await RoleManager.UpdateAsync(editedRole);
            if (!result.Succeeded) {
                return ProcessErrors(result.Errors);
            }

            return RedirectToPage();
        }

        public async Task<IActionResult> OnPostCreate(AppRole newRole) {
            IdentityResult result = await RoleManager.CreateAsync(newRole);
            if (!result.Succeeded) {
                return ProcessErrors(result.Errors);
            }
            return RedirectToPage();
        }

        private IActionResult ProcessErrors(IEnumerable<IdentityError> errors) {
            foreach (IdentityError err in errors) {
                ModelState.AddModelError("", err.Description);
            }
            return Page();
        }
    }
}
