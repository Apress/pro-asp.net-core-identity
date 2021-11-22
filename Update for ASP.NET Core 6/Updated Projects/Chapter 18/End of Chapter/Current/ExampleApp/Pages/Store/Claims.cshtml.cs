using System;
using System.Collections.Generic;
using System.Linq;
using System.Security.Claims;
using System.Threading.Tasks;
using Microsoft.AspNetCore.Identity;
using Microsoft.AspNetCore.Mvc;
using Microsoft.AspNetCore.Mvc.RazorPages;
using ExampleApp.Identity;

namespace ExampleApp.Pages.Store {

    public class ClaimsModel : PageModel {

        public ClaimsModel(UserManager<AppUser> userMgr) => UserManager = userMgr;

        public UserManager<AppUser> UserManager { get; set; }

        public AppUser AppUserObject { get; set; } = new AppUser();

        public IList<Claim> Claims { get; set; } = new List<Claim>();

        public string GetName(string claimType) =>
            (Uri.IsWellFormedUriString(claimType, UriKind.Absolute)
                ? System.IO.Path.GetFileName(new Uri(claimType).LocalPath)
                : claimType).ToUpper();

        public async Task OnGetAsync(string id) {
            if (id != null) {
                AppUserObject = await UserManager.FindByIdAsync(id) ?? new AppUser();
                Claims = (await UserManager.GetClaimsAsync(AppUserObject))
                    .OrderBy(c => c.Type).ThenBy(c => c.Value).ToList();
            }
        }

        public async Task<IActionResult> OnPostAdd(string id, string type,
                string value) {
            AppUser user = await UserManager.FindByIdAsync(id);
            await UserManager.AddClaimAsync(user, new Claim(type, value));
            return RedirectToPage();
        }

        public async Task<IActionResult> OnPostEdit(string id, string oldType,
                string type, string oldValue, string value) {
            AppUser user = await UserManager.FindByIdAsync(id);
            if (user != null) {
                await UserManager.ReplaceClaimAsync(user,
                    new Claim(oldType, oldValue), new Claim(type, value));
            }
            return RedirectToPage();
        }

        public async Task<IActionResult> OnPostDelete(string id, string type,
                string value) {
            AppUser user = await UserManager.FindByIdAsync(id);
            await UserManager.RemoveClaimAsync(user, new Claim(type, value));
            return RedirectToPage();
        }
    }
}
