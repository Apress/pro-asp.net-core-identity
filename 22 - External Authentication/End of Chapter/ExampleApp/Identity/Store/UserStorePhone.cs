using Microsoft.AspNetCore.Identity;
using System.Threading;
using System.Threading.Tasks;

namespace ExampleApp.Identity.Store {
    public partial class UserStore : IUserPhoneNumberStore<AppUser> {
        public Task<string> GetPhoneNumberAsync(AppUser user,
            CancellationToken token) => Task.FromResult(user.PhoneNumber);

        public Task SetPhoneNumberAsync(AppUser user, string phoneNumber,
                CancellationToken token) {
            user.PhoneNumber = phoneNumber;
            return Task.CompletedTask;
        }

        public Task<bool> GetPhoneNumberConfirmedAsync(AppUser user,
            CancellationToken token) => Task.FromResult(user.PhoneNumberConfirmed);

        public Task SetPhoneNumberConfirmedAsync(AppUser user, bool confirmed,
                CancellationToken token) {
            user.PhoneNumberConfirmed = confirmed;
            return Task.CompletedTask;
        }
    }
}
