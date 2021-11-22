using Microsoft.AspNetCore.Identity;
using System.Linq;

namespace ExampleApp.Identity.Store {

    public partial class UserStore : IQueryableUserStore<AppUser> {

        public IQueryable<AppUser> Users => users.Values
            .Select(user => user.Clone()).AsQueryable<AppUser>();
    }
}
