using Microsoft.AspNetCore.Identity;
using Microsoft.AspNetCore.Mvc;

namespace IdentityApp.Pages.Identity.Admin {

    public class LockoutsModel : AdminPageModel {

        public LockoutsModel(UserManager<IdentityUser> usrMgr)
            => UserManager = usrMgr;

        public UserManager<IdentityUser> UserManager { get; set; }

        public IEnumerable<IdentityUser> LockedOutUsers { get; set; } = Enumerable.Empty<IdentityUser>();
        public IEnumerable<IdentityUser> OtherUsers { get; set; } = Enumerable.Empty<IdentityUser>();

        public async Task<TimeSpan> TimeLeft(IdentityUser user)
            => (await UserManager.GetLockoutEndDateAsync(user))
                .GetValueOrDefault().Subtract(DateTimeOffset.Now);

        public void OnGet() {
            LockedOutUsers = UserManager.Users.Where(user => user.LockoutEnd.HasValue
                    && user.LockoutEnd.Value > DateTimeOffset.Now)
                .OrderBy(user => user.Email).ToList();
            OtherUsers = UserManager.Users.Where(user => !user.LockoutEnd.HasValue
                    || user.LockoutEnd.Value <= DateTimeOffset.Now)
                 .OrderBy(user => user.Email).ToList();
        }

        public async Task<IActionResult> OnPostLockAsync(string id) {
            IdentityUser user = await UserManager.FindByIdAsync(id);
            await UserManager.SetLockoutEnabledAsync(user, true);
            await UserManager.SetLockoutEndDateAsync(user,
                DateTimeOffset.Now.AddDays(5));
            await UserManager.UpdateSecurityStampAsync(user);
            return RedirectToPage();
        }

        public async Task<IActionResult> OnPostUnlockAsync(string id) {
            IdentityUser user = await UserManager.FindByIdAsync(id);
            await UserManager.SetLockoutEndDateAsync(user, null);
            return RedirectToPage();
        }
    }
}
