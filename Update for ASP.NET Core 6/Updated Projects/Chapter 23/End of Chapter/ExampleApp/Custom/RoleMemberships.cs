using Microsoft.AspNetCore.Http;
using System.Security.Claims;
using System.Security.Principal;
using System.Threading.Tasks;

namespace ExampleApp.Custom {

    public class RoleMemberships {
        private RequestDelegate next;

        public RoleMemberships(RequestDelegate requestDelegate)
                => next = requestDelegate;

        public async Task Invoke(HttpContext context) {
            IIdentity? mainIdent = context.User.Identity;
            if (mainIdent?.IsAuthenticated == true && mainIdent.Name != null 
                    && UsersAndClaims.Claims.ContainsKey(mainIdent.Name)) {
                ClaimsIdentity ident = new ClaimsIdentity("Roles");
                ident.AddClaim(new Claim(ClaimTypes.Name, mainIdent.Name));
                ident.AddClaims(UsersAndClaims.Claims[mainIdent.Name]);
                context.User.AddIdentity(ident);
            }
            await next(context);
        }
    }
}
