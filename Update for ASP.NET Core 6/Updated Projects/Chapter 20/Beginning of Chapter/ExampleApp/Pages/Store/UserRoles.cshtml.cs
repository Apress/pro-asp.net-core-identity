using ExampleApp.Identity;
using Microsoft.AspNetCore.Identity;
using Microsoft.AspNetCore.Mvc;
using Microsoft.AspNetCore.Mvc.RazorPages;
using System.Security.Claims;
using Microsoft.AspNetCore.Mvc.Rendering;

#pragma warning disable CS8601
#pragma warning disable CS8603

namespace ExampleApp.Pages.Store {

    public class UserRolesModel : PageModel {

        public UserRolesModel(UserManager<AppUser> userManager,
                RoleManager<AppRole> roleManager) {
            UserManager = userManager;
            RoleManager = roleManager;
        }

        public UserManager<AppUser> UserManager { get; set; }
        public RoleManager<AppRole> RoleManager { get; set; }

        public IEnumerable<string> Roles { get; set; } = Enumerable.Empty<string>();
        public SelectList? AvailableRoles { get; set; } 

        [BindProperty(SupportsGet = true)]
        public string? Id { get; set; }

        public async void OnGet() {
            AppUser user = await GetUser();
            if (user != null) {
                //Roles = await UserManager.GetRolesAsync(user);
                Roles = (await UserManager.GetClaimsAsync(user))?
                    .Where(c => c.Type == ClaimTypes.Role).Select(c => c.Value) 
                        ?? Enumerable.Empty<string>();
                AvailableRoles = new SelectList(RoleManager.Roles
                    .OrderBy(r => r.Name).Select(r => r.Name).Except(Roles));
            }
        }

        public async Task<IActionResult> OnPostAdd(string newRole) {
            //await UserManager.AddToRoleAsync(await GetUser(), newRole);
            await UserManager.AddClaimAsync(await GetUser(),
                new Claim(ClaimTypes.Role, newRole));
            return RedirectToPage();
        }

        public async Task<IActionResult> OnPostDelete(string role) {
            await UserManager.RemoveFromRoleAsync(await GetUser(), role);
            return RedirectToPage();
        }

        private Task<AppUser> GetUser() => Id == null
            ? null : UserManager.FindByIdAsync(Id);
    }
}
