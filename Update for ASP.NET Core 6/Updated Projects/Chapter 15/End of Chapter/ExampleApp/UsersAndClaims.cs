using System;
using System.Collections.Generic;
using System.Linq;
using System.Security.Claims;

namespace ExampleApp {
    public static class UsersAndClaims {
        public static string[] Schemes
             = new string[] { "TestScheme", "OtherScheme" };

        public static Dictionary<string, IEnumerable<string>> UserData
            = new Dictionary<string, IEnumerable<string>> {
               { "Alice", new [] { "User", "Administrator" } },
               { "Bob", new [] { "User" } },
               { "Charlie", new [] { "User"} }
            };

        public static string[] Users => UserData.Keys.ToArray();

        public static Dictionary<string, IEnumerable<Claim>> Claims =>
            UserData.ToDictionary(kvp => kvp.Key,
                kvp => kvp.Value.Select(role => new Claim(ClaimTypes.Role, role)),
                StringComparer.InvariantCultureIgnoreCase);

        public static IEnumerable<ClaimsPrincipal> GetUsers() {
            foreach (string scheme in Schemes) {
                foreach (var kvp in Claims) {
                    ClaimsIdentity ident = new ClaimsIdentity(scheme);
                    ident.AddClaim(new Claim(ClaimTypes.Name, kvp.Key));
                    ident.AddClaims(kvp.Value);
                    yield return new ClaimsPrincipal(ident);
                }
            }
        }
    }
}
