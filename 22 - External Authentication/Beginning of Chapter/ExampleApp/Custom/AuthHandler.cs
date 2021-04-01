using Microsoft.AspNetCore.Authentication;
using Microsoft.AspNetCore.Http;
using System.Security.Claims;
using System.Threading.Tasks;

namespace ExampleApp.Custom {

    public class AuthHandler : IAuthenticationSignInHandler {
        private HttpContext context;
        private AuthenticationScheme scheme;

        public Task InitializeAsync(AuthenticationScheme authScheme,
                HttpContext httpContext) {
            context = httpContext;
            scheme = authScheme;
            return Task.CompletedTask;
        }

        public Task<AuthenticateResult> AuthenticateAsync() {
            AuthenticateResult result;
            string user = context.Request.Cookies["authUser"];
            if (user != null) {
                Claim claim = new Claim(ClaimTypes.Name, user);
                ClaimsIdentity ident = new ClaimsIdentity(scheme.Name);
                ident.AddClaim(claim);
                result = AuthenticateResult.Success(
                    new AuthenticationTicket(new ClaimsPrincipal(ident),
                        scheme.Name));
            } else {
                result = AuthenticateResult.NoResult();
            }
            return Task.FromResult(result);
        }

        public Task ChallengeAsync(AuthenticationProperties properties) {
            //context.Response.StatusCode = StatusCodes.Status401Unauthorized;
            context.Response.Redirect("/signin/401");
            return Task.CompletedTask;
        }

        public Task ForbidAsync(AuthenticationProperties properties) {
            //context.Response.StatusCode = StatusCodes.Status403Forbidden;
            context.Response.Redirect("/signin/403");
            return Task.CompletedTask;
        }

        public Task SignInAsync(ClaimsPrincipal user,
                AuthenticationProperties properties) {
            context.Response.Cookies.Append("authUser", user.Identity.Name);
            return Task.CompletedTask;
        }

        public Task SignOutAsync(AuthenticationProperties properties) {
            context.Response.Cookies.Delete("authUser");
            return Task.CompletedTask;
        }
    }
}
