using Microsoft.AspNetCore.Identity;
using System.Collections.Concurrent;
using System.Threading;
using System.Threading.Tasks;

namespace ExampleApp.Identity.Store {

    public partial class UserStore : IUserStore<AppUser> {
        private ConcurrentDictionary<string, AppUser> users
            = new ConcurrentDictionary<string, AppUser>();

        public Task<IdentityResult> CreateAsync(AppUser user,
                CancellationToken token) {
            if (!users.ContainsKey(user.Id) && users.TryAdd(user.Id, user)) {
                return Task.FromResult(IdentityResult.Success);
            }
            return Task.FromResult(Error);
        }

        public Task<IdentityResult> DeleteAsync(AppUser user, CancellationToken token) {
            AppUser? outUser;
            if (users.ContainsKey(user.Id) && users.TryRemove(user.Id, out outUser)) {
                return Task.FromResult(IdentityResult.Success);
            }
            return Task.FromResult(Error);
        }

        public Task<IdentityResult> UpdateAsync(AppUser user,
                CancellationToken token) {
            if (users.ContainsKey(user.Id)) {
                users[user.Id].UpdateFrom(user);
                return Task.FromResult(IdentityResult.Success);
            }
            return Task.FromResult(Error);
        }

        public void Dispose() {
            // do nothing
        }

        private IdentityResult Error => IdentityResult.Failed(new IdentityError {
            Code = "StorageFailure",
            Description = "User Store Error"
        });
    }
}
