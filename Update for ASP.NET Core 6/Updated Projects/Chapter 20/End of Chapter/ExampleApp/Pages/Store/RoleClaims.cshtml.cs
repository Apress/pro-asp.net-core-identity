using ExampleApp.Identity;
using Microsoft.AspNetCore.Identity;
using Microsoft.AspNetCore.Mvc;
using Microsoft.AspNetCore.Mvc.RazorPages;
using System.Collections.Generic;
using System.Linq;
using System.Security.Claims;
using System.Threading.Tasks;

namespace ExampleApp.Pages.Store {

    public class RoleClaimsModel : PageModel {

        public RoleClaimsModel(RoleManager<AppRole> roleManager)
            => RoleManager = roleManager;

        public RoleManager<AppRole> RoleManager { get; set; }

        public AppRole Role { get; set; } = new();

        public IEnumerable<Claim> Claims => Role.Claims ?? new List<Claim>();

        public async Task OnGet(string id) {
            Role = await RoleManager.FindByIdAsync(id);
        }

        public async Task<IActionResult> OnPostAdd(string id, string type,
                string value) {
            Role = await RoleManager.FindByIdAsync(id);
            await RoleManager.AddClaimAsync(Role, new Claim(type, value));
            return RedirectToPage();
        }

        public async Task<IActionResult> OnPostEdit(string id, string type,
                string value, string oldType, string oldValue) {
            Role = await RoleManager.FindByIdAsync(id);
            await RoleManager.RemoveClaimAsync(Role, new Claim(oldType, oldValue));
            await RoleManager.AddClaimAsync(Role, new Claim(type, value));
            return RedirectToPage();
        }

        public async Task<IActionResult> OnPostDelete(string id, string type,
                string value) {
            Role = await RoleManager.FindByIdAsync(id);
            await RoleManager.RemoveClaimAsync(Role, new Claim(type, value));
            return RedirectToPage();
        }
    }
}
