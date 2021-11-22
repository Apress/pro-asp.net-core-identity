using Microsoft.AspNetCore.Http;
using System.Security.Claims;
using System.Threading.Tasks;

namespace ExampleApp.Custom {

    public class CustomAuthentication {
        private RequestDelegate next;

        public CustomAuthentication(RequestDelegate requestDelegate)
                => next = requestDelegate;

        public async Task Invoke(HttpContext context) {
            //string user = context.Request.Query["user"];
            string? user = context.Request.Cookies["authUser"];
            if (user != null) {
                Claim claim = new Claim(ClaimTypes.Name, user);
                ClaimsIdentity ident = new ClaimsIdentity("QueryStringValue");
                ident.AddClaim(claim);
                context.User = new ClaimsPrincipal(ident);
            }
            await next(context);
        }
    }
}
