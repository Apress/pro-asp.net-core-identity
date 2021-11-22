using Microsoft.AspNetCore.Identity;
using System.Collections.Generic;
using System.Security.Claims;
using System.Linq;

namespace ExampleApp.Identity.Store {

    public partial class RoleStore {

        public ILookupNormalizer Normalizer { get; set; }

        public RoleStore(ILookupNormalizer normalizer) {
            Normalizer = normalizer;
            SeedStore();
        }

        private void SeedStore() {

            var roleData = new List<string> {
                "Administrator", "User", "Sales", "Support"
            };

            var claims = new Dictionary<string, IEnumerable<Claim>> {
                { "Administrator", new [] { new Claim("AccessUserData", "true"),
                    new Claim(ClaimTypes.Role, "Support") } },
                {  "Support", new [] { new Claim(ClaimTypes.Role, "User" )} }
            };

            int idCounter = 0;

            foreach (string roleName in roleData) {
                AppRole role = new AppRole {
                    Id = (++idCounter).ToString(),
                    Name = roleName,
                    NormalizedName = Normalizer.NormalizeName(roleName)
                };
                if (claims.ContainsKey(roleName)) {
                    role.Claims = claims[roleName].ToList<Claim>();
                }
                roles.TryAdd(role.Id, role);
            }
        }
    }
}
