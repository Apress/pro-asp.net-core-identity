using Microsoft.AspNetCore.Identity;
using System.Security.Claims;
using System.Threading.Tasks;

namespace ExampleApp.Identity {
    public class AppUserClaimsPrincipalFactory :
        IUserClaimsPrincipalFactory<AppUser> {

        public Task<ClaimsPrincipal> CreateAsync(AppUser user) {
            ClaimsIdentity identity
                = new ClaimsIdentity(IdentityConstants.ApplicationScheme);
            identity.AddClaims(new[] {
                new Claim(ClaimTypes.NameIdentifier, user.Id),
                new Claim(ClaimTypes.Name, user.UserName),
                new Claim(ClaimTypes.Email, user.EmailAddress)
            });
            if (!string.IsNullOrEmpty(user.Hobby)) {
                identity.AddClaim(new Claim("Hobby", user.Hobby));
            }
            if (!string.IsNullOrEmpty(user.FavoriteFood)) {
                identity.AddClaim(new Claim("FavoriteFood", user.FavoriteFood));
            }
            if (user.Claims != null) {
                identity.AddClaims(user.Claims);
            }
            return Task.FromResult(new ClaimsPrincipal(identity));
        }
    }
}
