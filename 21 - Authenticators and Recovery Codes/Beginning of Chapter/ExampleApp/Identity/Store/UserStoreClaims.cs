using Microsoft.AspNetCore.Identity;
using Microsoft.VisualBasic;
using System;
using System.Collections.Generic;
using System.Linq;
using System.Security.Claims;
using System.Threading;
using System.Threading.Tasks;

namespace ExampleApp.Identity.Store {
    public partial class UserStore : IUserClaimStore<AppUser>,
            IEqualityComparer<Claim> {

        public Task AddClaimsAsync(AppUser user, IEnumerable<Claim> claims,
                CancellationToken token) {
            if (user.Claims == null) {
                user.Claims = new List<Claim>();
            }
            foreach (Claim claim in claims) {
                user.Claims.Add(claim);
            }
            return Task.CompletedTask;
        }

        public Task<IList<Claim>> GetClaimsAsync(AppUser user,
                CancellationToken token) => Task.FromResult(user.Claims);

        public Task RemoveClaimsAsync(AppUser user, IEnumerable<Claim> claims,
                CancellationToken token) {
            foreach (Claim c in user.Claims.Intersect(claims, this).ToList()) {
                user.Claims.Remove(c);
            }
            return Task.CompletedTask;
        }

        public async Task ReplaceClaimAsync(AppUser user, Claim oldclaim,
                Claim newClaim, CancellationToken token) {
            await RemoveClaimsAsync(user, new[] { oldclaim }, token);
            user.Claims.Add(newClaim);
        }

        public Task<IList<AppUser>> GetUsersForClaimAsync(Claim claim,
                CancellationToken token) =>
            Task.FromResult(
                Users.Where(u => u.Claims.Any(c => Equals(c, claim)))
                   .ToList() as IList<AppUser>);

        public bool Equals(Claim first, Claim second) =>
            first.Type == second.Type && string.Equals(first.Value, second.Value,
                    StringComparison.OrdinalIgnoreCase);

        public int GetHashCode(Claim claim) =>
            claim.Type.GetHashCode() + claim.Value.GetHashCode();
    }
}
