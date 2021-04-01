using ExampleApp.Identity;
using Microsoft.AspNetCore.Identity;
using Microsoft.AspNetCore.Mvc;
using Microsoft.AspNetCore.Mvc.RazorPages;
using System.Collections.Generic;
using System.Linq;
using System.Threading.Tasks;
using System.Security.Claims;

namespace ExampleApp.Pages.Store {

    public class UserRolesModel : PageModel {

        public UserRolesModel(UserManager<AppUser> userManager)
            => UserManager = userManager;

        public UserManager<AppUser> UserManager { get; set; }

        public IEnumerable<string> Roles { get; set; } = Enumerable.Empty<string>();

        [BindProperty(SupportsGet = true)]
        public string Id { get; set; }

        public async void OnGet() {
            AppUser user = await GetUser();
            if (user != null) {
                //Roles = await UserManager.GetRolesAsync(user);
                Roles = (await UserManager.GetClaimsAsync(user))?
                    .Where(c => c.Type == ClaimTypes.Role).Select(c => c.Value);
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
