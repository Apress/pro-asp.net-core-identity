using Microsoft.AspNetCore.Authentication;
using Microsoft.AspNetCore.Identity;
using System.Collections.Generic;
using System.Linq;
using System.Threading;
using System.Threading.Tasks;

namespace ExampleApp.Identity.Store {
    public partial class UserStore : IUserAuthenticationTokenStore<AppUser> {

        public Task<string> GetTokenAsync(AppUser user, string loginProvider,
                string name, CancellationToken cancelToken) {
            return Task.FromResult(user.AuthTokens?
                .FirstOrDefault(t => t.provider == loginProvider
                    && t.token.Name == name).token.Value);
        }

        public Task RemoveTokenAsync(AppUser user, string loginProvider,
                string name, CancellationToken cancelToken) {
            if (user.AuthTokens != null) {
                user.AuthTokens = user.AuthTokens.Where(t =>
                    t.provider != loginProvider
                        && t.token.Name != name).ToList();
            }
            return Task.CompletedTask;
        }

        public Task SetTokenAsync(AppUser user, string loginProvider,
             string name, string value, CancellationToken cancelToken) {
            if (user.AuthTokens == null) {
                user.AuthTokens = new List<(string, AuthenticationToken)>();
            }
            user.AuthTokens.Add((loginProvider, new AuthenticationToken {
                Name = name,
                Value = value
            }));
            return Task.CompletedTask;
        }
    }
}
