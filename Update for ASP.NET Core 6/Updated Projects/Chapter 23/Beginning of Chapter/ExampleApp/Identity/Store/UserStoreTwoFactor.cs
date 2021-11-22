using Microsoft.AspNetCore.Identity;
using System.Threading;
using System.Threading.Tasks;

namespace ExampleApp.Identity.Store {
    public partial class UserStore : IUserTwoFactorStore<AppUser> {

        public Task<bool> GetTwoFactorEnabledAsync(AppUser user,
            CancellationToken token) => Task.FromResult(user.TwoFactorEnabled);

        public Task SetTwoFactorEnabledAsync(AppUser user, bool enabled,
                CancellationToken token) {
            user.TwoFactorEnabled = enabled;
            return Task.CompletedTask;
        }
    }
}
