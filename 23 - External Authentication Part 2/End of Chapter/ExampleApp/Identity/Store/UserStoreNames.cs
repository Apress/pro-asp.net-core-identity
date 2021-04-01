using System.Threading;
using System.Threading.Tasks;

namespace ExampleApp.Identity.Store {

    public partial class UserStore {

        public Task<string> GetNormalizedUserNameAsync(AppUser user,
            CancellationToken token)
                 => Task.FromResult(user.NormalizedUserName);

        public Task<string> GetUserIdAsync(AppUser user,
            CancellationToken token)
                => Task.FromResult(user.Id);

        public Task<string> GetUserNameAsync(AppUser user,
            CancellationToken token)
                => Task.FromResult(user.UserName);

        public Task SetNormalizedUserNameAsync(AppUser user,
            string normalizedName, CancellationToken token)
                => Task.FromResult(user.NormalizedUserName = normalizedName);

        public Task SetUserNameAsync(AppUser user, string userName,
            CancellationToken token)
                => Task.FromResult(user.UserName = userName);
    }
}
