using System.Security.Claims;

namespace ExampleApp.Custom {
    public class ClaimsReporter {
        private RequestDelegate next;

        public ClaimsReporter(RequestDelegate requestDelegate)
                => next = requestDelegate;

        public async Task Invoke(HttpContext context) {

            ClaimsPrincipal p = context.User;

            Console.WriteLine($"User: {p.Identity?.Name}");
            Console.WriteLine($"Authenticated: {p.Identity?.IsAuthenticated}");
            Console.WriteLine("Authentication Type "
                + p.Identity?.AuthenticationType);

            Console.WriteLine($"Identities: {p.Identities.Count()}");
            foreach (ClaimsIdentity ident in p.Identities) {
                Console.WriteLine($"Auth type: {ident.AuthenticationType},"
                    + $" {ident.Claims.Count()} claims");
                foreach (Claim claim in ident.Claims) {
                    Console.WriteLine($"Type: {GetName(claim.Type)}, "
                        + $"Value: {claim.Value}, Issuer: {claim.Issuer}");
                }
            }
            await next(context);
        }

        private string GetName(string claimType) =>
            Path.GetFileName(new Uri(claimType).LocalPath);
    }
}
