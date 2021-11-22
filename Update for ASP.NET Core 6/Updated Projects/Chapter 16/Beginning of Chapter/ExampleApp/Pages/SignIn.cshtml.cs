using Microsoft.AspNetCore.Authentication;
using Microsoft.AspNetCore.Mvc;
using Microsoft.AspNetCore.Mvc.RazorPages;
using Microsoft.AspNetCore.Mvc.Rendering;
using System.Security.Claims;

namespace ExampleApp.Pages {
    public class SignInModel : PageModel {

        public SelectList Users => new SelectList(UsersAndClaims.Users,
            User.Identity?.Name);

        public string Username { get; set; } = String.Empty;

        public int? Code { get; set; }

        public void OnGet(int? code) {
            Code = code;
            Username = User.Identity?.Name ?? "(No Signed In User)";
        }

        public async Task<ActionResult> OnPost(string username,
                [FromQuery] string returnUrl) {

            Claim claim = new Claim(ClaimTypes.Name, username);
            ClaimsIdentity ident = new ClaimsIdentity("simpleform");
            ident.AddClaim(claim);
            await HttpContext.SignInAsync(new ClaimsPrincipal(ident));
            return Redirect(returnUrl ?? "/signin");
        }
    }
}
