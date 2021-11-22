using Microsoft.AspNetCore.Identity;

namespace ExampleApp.Identity.Store {

    public class Normalizer : ILookupNormalizer {

        public string NormalizeName(string name)
            => name.Normalize().ToLowerInvariant();

        public string NormalizeEmail(string email)
            => email.Normalize().ToLowerInvariant();
    }
}
