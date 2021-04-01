using System.Collections.Generic;
using System.Linq;
using System.Security.Claims;

namespace IdentityApp.Models {

    public static class ApplicationClaimTypes {
        public const string Country = ClaimTypes.Country;
        public const string SecurityClearance = "SecurityClearance";

        public static string GetDisplayName(this Claim claim)
            => GetDisplayName(claim.Type);

        public static string GetDisplayName(string claimType)
            => typeof(ClaimTypes).GetFields().Where(field =>
                    field.GetRawConstantValue().ToString() == claimType)
                        .Select(field => field.Name)
                        .FirstOrDefault() ?? claimType;

        public static IEnumerable<(string type, string display)> AppClaimTypes
            = new[] { Country, SecurityClearance }.Select(c =>
                (c, GetDisplayName(c)));
    }
}
