using Microsoft.AspNetCore.Identity;

namespace ExampleApp.Identity.Store {

    public partial class UserStore : IUserPasswordStore<AppUser> {

        public Task<string?> GetPasswordHashAsync(AppUser user,
            CancellationToken token) => Task.FromResult(user.PasswordHash);

        public Task<bool> HasPasswordAsync(AppUser user, CancellationToken token)
            => Task.FromResult(!string.IsNullOrEmpty(user.PasswordHash));

        public Task SetPasswordHashAsync(AppUser user, string passwordHash,
                CancellationToken token) {
            user.PasswordHash = passwordHash;
            return Task.CompletedTask;
        }
    }
}
