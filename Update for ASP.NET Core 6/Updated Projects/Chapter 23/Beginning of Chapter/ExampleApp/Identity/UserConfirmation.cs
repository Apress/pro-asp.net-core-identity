using Microsoft.AspNetCore.Identity;
using System.Linq;
using System.Threading.Tasks;

namespace ExampleApp.Identity {
    public class UserConfirmation : IUserConfirmation<AppUser> {

        public async Task<bool> IsConfirmedAsync(UserManager<AppUser> manager,
                AppUser user) =>
            await manager.IsInRoleAsync(user, "Administrator")
                || (await manager.GetClaimsAsync(user))
                    .Any(claim => claim.Type == "UserConfirmed"
                        && string.Compare(claim.Value, "true", true) == 0);
    }
}
