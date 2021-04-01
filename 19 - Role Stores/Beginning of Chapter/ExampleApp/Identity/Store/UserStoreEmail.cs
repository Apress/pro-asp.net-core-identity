using Microsoft.AspNetCore.Identity;
using System.Linq;
using System.Threading;
using System.Threading.Tasks;

namespace ExampleApp.Identity.Store {

    public partial class UserStore : IUserEmailStore<AppUser> {

        public Task<AppUser> FindByEmailAsync(string normalizedEmail,
                CancellationToken token) =>
            Task.FromResult(Users.FirstOrDefault(user =>
                user.NormalizedEmailAddress == normalizedEmail));

        public Task<string> GetEmailAsync(AppUser user,
                CancellationToken token) =>
            Task.FromResult(user.EmailAddress);

        public Task SetEmailAsync(AppUser user, string email,
                CancellationToken token) {
            user.EmailAddress = email;
            return Task.CompletedTask;
        }

        public Task<string> GetNormalizedEmailAsync(AppUser user,
                CancellationToken token) =>
            Task.FromResult(user.NormalizedEmailAddress);

        public Task SetNormalizedEmailAsync(AppUser user, string normalizedEmail,
                CancellationToken token) {
            user.NormalizedEmailAddress = normalizedEmail;
            return Task.CompletedTask;
        }

        public Task<bool> GetEmailConfirmedAsync(AppUser user,
                CancellationToken token) =>
            Task.FromResult(user.EmailAddressConfirmed);

        public Task SetEmailConfirmedAsync(AppUser user, bool confirmed,
                CancellationToken token) {
            user.EmailAddressConfirmed = confirmed;
            return Task.CompletedTask;
        }
    }
}
