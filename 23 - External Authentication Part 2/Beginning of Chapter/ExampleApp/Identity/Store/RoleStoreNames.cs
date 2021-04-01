using System.Threading;
using System.Threading.Tasks;

namespace ExampleApp.Identity.Store {

    public partial class RoleStore {

        public Task<string> GetRoleIdAsync(AppRole role, CancellationToken token)
            => Task.FromResult(role.Id);

        public Task<string> GetRoleNameAsync(AppRole role, CancellationToken token)
            => Task.FromResult(role.Name);

        public Task SetRoleNameAsync(AppRole role, string roleName,
                CancellationToken token) {
            role.Name = roleName;
            return Task.CompletedTask;
        }

        public Task<string> GetNormalizedRoleNameAsync(AppRole role,
           CancellationToken token) => Task.FromResult(role.NormalizedName);

        public Task SetNormalizedRoleNameAsync(AppRole role, string normalizedName,
                CancellationToken token) {
            role.NormalizedName = normalizedName;
            return Task.CompletedTask;
        }
    }
}
