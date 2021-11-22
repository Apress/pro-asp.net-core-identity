using Microsoft.AspNetCore.Identity;
using System.Collections.Generic;
using System.Linq;
using System.Security.Claims;
using System.Threading;
using System.Threading.Tasks;

namespace ExampleApp.Identity.Store {
    public partial class RoleStore : IRoleClaimStore<AppRole> {

        public Task AddClaimAsync(AppRole role, Claim claim,
                CancellationToken token = default) {
            role.Claims.Add(claim);
            return Task.CompletedTask;
        }

        public Task<IList<Claim>> GetClaimsAsync(AppRole role,
                CancellationToken token = default) =>
            Task.FromResult(role.Claims ?? new List<Claim>());

        public Task RemoveClaimAsync(AppRole role, Claim claim,
                CancellationToken token = default) {
            role.Claims = role.Claims.Where(c => !(string.Equals(c.Type, claim.Type)
                && string.Equals(c.Value, claim.Value))).ToList<Claim>();
            return Task.CompletedTask;
        }
    }
}
