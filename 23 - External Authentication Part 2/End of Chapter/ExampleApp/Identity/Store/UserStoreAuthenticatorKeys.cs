using Microsoft.AspNetCore.Identity;
using System.Threading;
using System.Threading.Tasks;

namespace ExampleApp.Identity.Store {
    public partial class UserStore : IUserAuthenticatorKeyStore<AppUser> {

        public Task<string> GetAuthenticatorKeyAsync(AppUser user,
                CancellationToken cancellationToken)
            => Task.FromResult(user.AuthenticatorKey);

        public Task SetAuthenticatorKeyAsync(AppUser user, string key,
                CancellationToken cancellationToken) {
            user.AuthenticatorKey = key;
            return Task.CompletedTask;
        }
    }
}
