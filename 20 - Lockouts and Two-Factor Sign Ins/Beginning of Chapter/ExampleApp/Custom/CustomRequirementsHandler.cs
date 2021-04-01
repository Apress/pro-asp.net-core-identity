using Microsoft.AspNetCore.Authorization;
using System;
using System.Linq;
using System.Threading.Tasks;

namespace ExampleApp.Custom {
    public class CustomRequirementHandler : IAuthorizationHandler {

        public Task HandleAsync(AuthorizationHandlerContext context) {
            foreach (CustomRequirement req in
                context.PendingRequirements.OfType<CustomRequirement>().ToList()) {
                if (context.User.Identities.Any(ident => string.Equals(ident.Name,
                        req.Name, StringComparison.OrdinalIgnoreCase))) {
                    context.Succeed(req);
                }
            }
            return Task.CompletedTask;
        }
    }
}
