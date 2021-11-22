using System.Linq;
using System.Threading;
using System.Threading.Tasks;

#pragma warning disable CS8619

namespace ExampleApp.Identity.Store {

    public partial class UserStore {

        public Task<AppUser> FindByIdAsync(string userId, CancellationToken token) {
            return Task.FromResult(users.ContainsKey(userId) ? users[userId].Clone() : null);
        }

        public Task<AppUser> FindByNameAsync(string normalizedUserName,
                CancellationToken token) =>
            Task.FromResult(users.Values.FirstOrDefault(user =>
                user.NormalizedUserName == normalizedUserName)?.Clone());
    }
}
