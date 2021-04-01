using Microsoft.AspNetCore.Http;
using System.Threading.Tasks;

namespace ExampleApp.Custom {

    public class CustomAuthorization {
        private RequestDelegate next;

        public CustomAuthorization(RequestDelegate requestDelegate)
                => next = requestDelegate;

        public async Task Invoke(HttpContext context) {
            if (context.GetEndpoint()?.DisplayName == "secret") {
                if (context.User.Identity.IsAuthenticated) {
                    if (context.User.IsInRole("Administrator")) {
                        await next(context);
                    } else {
                        Forbid(context);
                    }
                } else {
                    Challenge(context);
                }
            } else {
                await next(context);
            }
        }

        public void Challenge(HttpContext context)
                => context.Response.StatusCode = StatusCodes.Status401Unauthorized;

        public void Forbid(HttpContext context)
                => context.Response.StatusCode = StatusCodes.Status403Forbidden;
    }
}
