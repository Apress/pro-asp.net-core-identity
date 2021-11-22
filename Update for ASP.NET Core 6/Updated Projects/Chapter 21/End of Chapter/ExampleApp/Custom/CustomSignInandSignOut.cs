using Microsoft.AspNetCore.Authentication;
using Microsoft.AspNetCore.Http;
using System.Threading.Tasks;
using System.Security.Claims;

namespace ExampleApp.Custom {
    public class CustomSignInAndSignOut {

        public static async Task SignIn(HttpContext context) {
            string user = context.Request.Query["user"];
            if (user != null) {
                Claim claim = new Claim(ClaimTypes.Name, user);
                ClaimsIdentity ident = new ClaimsIdentity("qsv");
                ident.AddClaim(claim);
                await context.SignInAsync(new ClaimsPrincipal(ident));
                await context.Response
                    .WriteAsync($"Authenticated user: {user}");
            } else {
                await context.ChallengeAsync();
            }
        }

        public static async Task SignOut(HttpContext context) {
            await context.SignOutAsync();
            await context.Response.WriteAsync("Signed out");
        }
    }
}
