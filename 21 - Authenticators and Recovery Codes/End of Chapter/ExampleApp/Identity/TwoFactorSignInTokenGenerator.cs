using Microsoft.AspNetCore.Identity;
using System.Threading.Tasks;

namespace ExampleApp.Identity {

    public class TwoFactorSignInTokenGenerator : SimpleTokenGenerator {

        protected override int CodeLength => 3;

        public override Task<bool> CanGenerateTwoFactorTokenAsync(
                UserManager<AppUser> manager, AppUser user) {
            return Task.FromResult(user.TwoFactorEnabled);
        }
    }
}
