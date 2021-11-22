using Microsoft.AspNetCore.Identity;
using System.Collections.Generic;
using System.Linq;
using System.Security.Claims;
using System.Threading;
using System.Threading.Tasks;

namespace ExampleApp.Identity.Store {
    public partial class UserStore : IUserRoleStore<AppUser> {

        public Task<IList<AppUser>> GetUsersInRoleAsync(string roleName,
                CancellationToken token)
            => GetUsersForClaimAsync(new Claim(ClaimTypes.Role, roleName), token);

        public async Task<IList<string>> GetRolesAsync(AppUser user,
                CancellationToken token)
            => (await GetClaimsAsync(user, token))
                .Where(claim => claim.Type == ClaimTypes.Role)
                .Distinct().Select(claim => Normalizer.NormalizeName(claim.Value))
                .ToList();

        public async Task<bool> IsInRoleAsync(AppUser user, string
                normalizedRoleName, CancellationToken token)
            => (await GetRolesAsync(user, token)).Any(role =>
                    Normalizer.NormalizeName(role) == normalizedRoleName);

        public Task AddToRoleAsync(AppUser user, string roleName,
                CancellationToken token)
            => AddClaimsAsync(user, GetClaim(roleName), token);

        public async Task RemoveFromRoleAsync(AppUser user,
                string normalizedRoleName, CancellationToken token) {
            IEnumerable<Claim> claimsToDelete = (await GetClaimsAsync(user, token))
                .Where(claim => claim.Type == ClaimTypes.Role
                    && Normalizer.NormalizeName(claim.Value) == normalizedRoleName);
            await RemoveClaimsAsync(user, claimsToDelete, token);
        }

        private IEnumerable<Claim> GetClaim(string role) =>
            new[] { new Claim(ClaimTypes.Role, role) };
    }
}
