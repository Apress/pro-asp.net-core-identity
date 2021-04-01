using Microsoft.AspNetCore.Authorization;
using Microsoft.AspNetCore.Http;
using Microsoft.AspNetCore.Mvc;
using Microsoft.AspNetCore.Mvc.Filters;
using Microsoft.Extensions.DependencyInjection;
using System;
using System.Threading.Tasks;

namespace ExampleApp.Identity {

    public class Full2FARequiredFilterAttribute : Attribute,
            IAsyncPageFilter, IAsyncActionFilter {

        public async Task OnActionExecutionAsync(ActionExecutingContext context,
                ActionExecutionDelegate next) {
            IActionResult result = await ApplyPolicy(context.HttpContext);
            if (result != null) {
                context.Result = result;
            } else {
                await next.Invoke();
            }
        }

        public async Task OnPageHandlerExecutionAsync(PageHandlerExecutingContext
                context, PageHandlerExecutionDelegate next) {
            IActionResult result = await ApplyPolicy(context.HttpContext);
            if (result != null) {
                context.Result = result;
            } else {
                await next.Invoke();
            }
        }

        public async Task<IActionResult> ApplyPolicy(HttpContext context) {
            IAuthorizationService authService =
                context.RequestServices.GetService<IAuthorizationService>();
            if (!(await authService.AuthorizeAsync(context.User,
                 "Full2FARequired")).Succeeded) {
                return new RedirectToPageResult("/Full2FARequired",
                    new { returnUrl = Path(context) });
            }
            return null;
        }

        public Task OnPageHandlerSelectionAsync(PageHandlerSelectedContext context) {
            return Task.CompletedTask;
        }

        private string Path(HttpContext context) =>
            $"{context.Request.Path}{context.Request.QueryString}";
    }
}
