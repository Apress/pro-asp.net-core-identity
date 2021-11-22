using Microsoft.AspNetCore.Identity;

namespace ExampleApp.Identity.Store {
    public partial class UserStore : IUserAuthenticatorKeyStore<AppUser> {

        public Task<string?> GetAuthenticatorKeyAsync(AppUser user,
                CancellationToken cancellationToken)
            => Task.FromResult(user.AuthenticatorKey);

        public Task SetAuthenticatorKeyAsync(AppUser user, string key,
                CancellationToken cancellationToken) {
            user.AuthenticatorKey = key;
            return Task.CompletedTask;
        }
    }
}
