using Microsoft.AspNetCore.Identity;
using Microsoft.AspNetCore.Mvc;
using System.Collections.Generic;
using System.ComponentModel.DataAnnotations;
using System.Linq;
using System.Threading.Tasks;
using Microsoft.Extensions.Configuration;

namespace IdentityApp.Pages.Identity.Admin {

    public class RolesModel : AdminPageModel {

        public RolesModel(UserManager<IdentityUser> userMgr,
                RoleManager<IdentityRole> roleMgr,
                IConfiguration config) {
            UserManager = userMgr;
            RoleManager = roleMgr;
            DashboardRole = config["Dashboard:Role"] ?? "Dashboard";
        }

        [BindProperty(SupportsGet = true)]
        public string Id { get; set; }

        public UserManager<IdentityUser> UserManager { get; set; }
        public RoleManager<IdentityRole> RoleManager { get; set; }

        public IList<string> CurrentRoles { get; set; } = new List<string>();
        public IList<string> AvailableRoles { get; set; } = new List<string>();

        public string DashboardRole { get; }

        private async Task SetProperties() {
            IdentityUser user = await UserManager.FindByIdAsync(Id);
            CurrentRoles = await UserManager.GetRolesAsync(user);
            AvailableRoles = RoleManager.Roles.Select(r => r.Name)
                .Where(r => !CurrentRoles.Contains(r)).ToList();
        }

        public async Task<IActionResult> OnGetAsync() {
            if (string.IsNullOrEmpty(Id)) {
                return RedirectToPage("Selectuser",
                    new { Label = "Edit Roles", Callback = "Roles" });
            }
            await SetProperties();
            return Page();
        }

        public async Task<IActionResult> OnPostAddToList(string role) {
            IdentityResult result =
                await RoleManager.CreateAsync(new IdentityRole(role));
            if (result.Process(ModelState)) {
                return RedirectToPage();
            }
            await SetProperties();
            return Page();
        }

        public async Task<IActionResult> OnPostDeleteFromList(string role) {
            IdentityRole idRole = await RoleManager.FindByNameAsync(role);
            IdentityResult result = await RoleManager.DeleteAsync(idRole);
            if (result.Process(ModelState)) {
                return RedirectToPage();
            }
            await SetProperties();
            return Page();
        }

        public async Task<IActionResult> OnPostAdd([Required] string role) {
            if (ModelState.IsValid) {
                IdentityResult result = IdentityResult.Success;
                if (result.Process(ModelState)) {
                    IdentityUser user = await UserManager.FindByIdAsync(Id);
                    if (!await UserManager.IsInRoleAsync(user, role)) {
                        result = await UserManager.AddToRoleAsync(user, role);
                    }
                    if (result.Process(ModelState)) {
                        return RedirectToPage();
                    }
                }
            }
            await SetProperties();
            return Page();
        }

        public async Task<IActionResult> OnPostDelete(string role) {
            IdentityUser user = await UserManager.FindByIdAsync(Id);
            if (await UserManager.IsInRoleAsync(user, role)) {
                await UserManager.RemoveFromRoleAsync(user, role);
            }
            return RedirectToPage();
        }
    }
}
