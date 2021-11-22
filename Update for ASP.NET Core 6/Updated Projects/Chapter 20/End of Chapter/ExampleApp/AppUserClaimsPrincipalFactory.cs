using Microsoft.AspNetCore.Identity;
using System.Security.Claims;
using System.Threading.Tasks;

namespace ExampleApp.Identity {
    public class AppUserClaimsPrincipalFactory : IUserClaimsPrincipalFactory<AppUser> {

        public AppUserClaimsPrincipalFactory(UserManager<AppUser> userManager,
                RoleManager<AppRole> roleManager) {
            UserManager = userManager;
            RoleManager = roleManager;
        }

        public UserManager<AppUser> UserManager { get; set; }
        public RoleManager<AppRole> RoleManager { get; set; }

        public async Task<ClaimsPrincipal> CreateAsync(AppUser user) {
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

            if (UserManager.SupportsUserRole && RoleManager.SupportsRoleClaims) {
                foreach (string roleName in await UserManager.GetRolesAsync(user)) {
                    AppRole role = await RoleManager.FindByNameAsync(roleName);
                    if (role != null && role.Claims != null) {
                        identity.AddClaims(role.Claims);
                    }
                }
            }

            return new ClaimsPrincipal(identity);
        }
    }
}
