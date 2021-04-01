using Microsoft.AspNetCore.Identity;
using System.Linq;
using System.Threading.Tasks;

namespace ExampleApp.Identity {
    public class EmailValidator : IUserValidator<AppUser> {
        private static string[] AllowedDomains = new[] { "example.com", "acme.com" };
        private static IdentityError err
            = new IdentityError { Description = "Email address domain not allowed" };

        public EmailValidator(ILookupNormalizer normalizer) {
            Normalizer = normalizer;
        }

        private ILookupNormalizer Normalizer { get; set; }

        public Task<IdentityResult> ValidateAsync(UserManager<AppUser> manager,
                AppUser user) {
            string normalizedEmail = Normalizer.NormalizeEmail(user.EmailAddress);
            if (AllowedDomains.Any(domain =>
                    normalizedEmail.EndsWith($"@{domain}"))) {
                return Task.FromResult(IdentityResult.Success);
            }
            return Task.FromResult(IdentityResult.Failed(err));
        }
    }
}
