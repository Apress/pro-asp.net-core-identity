using Microsoft.AspNetCore.Identity;
using System.Collections.Concurrent;
using System.Threading;
using System.Threading.Tasks;

namespace ExampleApp.Identity.Store {
    public partial class RoleStore : IRoleStore<AppRole> {
        private ConcurrentDictionary<string, AppRole> roles
            = new ConcurrentDictionary<string, AppRole>();

        public Task<IdentityResult> CreateAsync(AppRole role,
                CancellationToken token) {
            if (!roles.ContainsKey(role.Id) && roles.TryAdd(role.Id, role)) {
                return Task.FromResult(IdentityResult.Success);
            }
            return Task.FromResult(Error);
        }

        public Task<IdentityResult> DeleteAsync(AppRole role,
                CancellationToken token) {
            if (roles.ContainsKey(role.Id) && roles.TryRemove(role.Id, out role)) {
                return Task.FromResult(IdentityResult.Success);
            }
            return Task.FromResult(Error);
        }

        public Task<IdentityResult> UpdateAsync(AppRole role,
                CancellationToken token) {
            if (roles.ContainsKey(role.Id)) {
                roles[role.Id].UpdateFrom(role);
                return Task.FromResult(IdentityResult.Success);
            }
            return Task.FromResult(Error);
        }

        public void Dispose() {
            // do nothing
        }

        private IdentityResult Error => IdentityResult.Failed(new IdentityError {
            Code = "StorageFailure",
            Description = "Role Store Error"
        });
    }
}
