using Microsoft.AspNetCore.Identity;
using Microsoft.AspNetCore.Mvc;
using System.Security.Claims;
using System.Threading.Tasks;

namespace IdentityApp.Pages.Identity.Admin {

    public class ViewClaimsPrincipalModel : AdminPageModel {

        public ViewClaimsPrincipalModel(UserManager<IdentityUser> usrMgr,
                SignInManager<IdentityUser> signMgr) {
            UserManager = usrMgr;
            SignInManager = signMgr;
        }

        [BindProperty(SupportsGet = true)]
        public string Id { get; set; }

        [BindProperty(SupportsGet = true)]
        public string Callback { get; set; }

        public UserManager<IdentityUser> UserManager { get; set; }
        public SignInManager<IdentityUser> SignInManager { get; set; }

        public ClaimsPrincipal Principal { get; set; }

        public async Task<IActionResult> OnGetAsync() {
            if (string.IsNullOrEmpty(Id)) {
                return RedirectToPage("Selectuser",
                    new {
                        Label = "View ClaimsPrincipal",
                        Callback = "ClaimsPrincipal"
                    });
            }
            IdentityUser user = await UserManager.FindByIdAsync(Id);
            Principal = await SignInManager.CreateUserPrincipalAsync(user);
            return Page();
        }
    }
}
