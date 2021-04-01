using System.Linq;
using System.Threading;
using System.Threading.Tasks;
using Microsoft.AspNetCore.Identity;

namespace ExampleApp.Identity.Store {

    public partial class RoleStore : IQueryableRoleStore<AppRole> {

        public Task<AppRole> FindByIdAsync(string id, CancellationToken token)
            => Task.FromResult(roles.ContainsKey(id) ? roles[id].Clone() : null);

        public Task<AppRole> FindByNameAsync(string name, CancellationToken token)
            => Task.FromResult(roles.Values.FirstOrDefault(r => r.NormalizedName ==
                   name)?.Clone());

        public IQueryable<AppRole> Roles =>
             roles.Values.Select(role => role.Clone()).AsQueryable<AppRole>();
    }
}
