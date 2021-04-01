using Microsoft.AspNetCore.Identity;
using System;
using System.Threading;
using System.Threading.Tasks;

namespace ExampleApp.Identity.Store {
    public partial class UserStore : IUserLockoutStore<AppUser> {

        public Task SetLockoutEnabledAsync(AppUser user, bool enabled,
                CancellationToken token) {
            user.CanUserBeLockedout = enabled;
            return Task.CompletedTask;
        }

        public Task<bool> GetLockoutEnabledAsync(AppUser user,
            CancellationToken token) => Task.FromResult(user.CanUserBeLockedout);

        public Task<int> GetAccessFailedCountAsync(AppUser user,
            CancellationToken token) => Task.FromResult(user.FailedSignInCount);

        public Task<int> IncrementAccessFailedCountAsync(AppUser user,
            CancellationToken token) => Task.FromResult(++user.FailedSignInCount);

        public Task ResetAccessFailedCountAsync(AppUser user,
            CancellationToken token) {
            user.FailedSignInCount = 0;
            return Task.CompletedTask;
        }

        public Task SetLockoutEndDateAsync(AppUser user, DateTimeOffset? lockoutEnd,
                CancellationToken token) {
            user.LockoutEnd = lockoutEnd;
            return Task.CompletedTask;
        }

        public Task<DateTimeOffset?> GetLockoutEndDateAsync(AppUser user,
            CancellationToken token) => Task.FromResult(user.LockoutEnd);
    }
}
