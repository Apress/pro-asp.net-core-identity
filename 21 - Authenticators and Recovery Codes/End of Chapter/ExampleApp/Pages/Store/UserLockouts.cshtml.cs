using ExampleApp.Identity;
using Microsoft.AspNetCore.Identity;
using Microsoft.AspNetCore.Mvc;
using Microsoft.AspNetCore.Mvc.RazorPages;
using System;
using System.Collections.Generic;
using System.Linq;
using System.Threading.Tasks;

namespace ExampleApp.Pages.Store {

    public class UserLockoutsModel : PageModel {

        public UserLockoutsModel(UserManager<AppUser> manager)
            => UserManager = manager;

        public UserManager<AppUser> UserManager { get; set; }

        public IEnumerable<AppUser> Users => UserManager.Users
             .OrderByDescending(u => UserManager.IsLockedOutAsync(u).Result)
             .ThenBy(u => u.UserName);

        public async Task<string> GetLockoutStatus(AppUser user) {
            if (await UserManager.IsLockedOutAsync(user)) {
                TimeSpan remaining = (await UserManager.GetLockoutEndDateAsync(user))
                    .GetValueOrDefault().Subtract(DateTimeOffset.Now);
                return $"Locked Out ({ remaining.Minutes } mins "
                    + $"{ remaining.Seconds} secs remaining)";
            }
            return "(No Lockout)";
        }

        public async Task<IActionResult> OnPost(string id, int mins) {
            await UserManager.SetLockoutEndDateAsync((await
                UserManager.FindByIdAsync(id)), DateTimeOffset.Now.AddMinutes(mins));
            return RedirectToPage();
        }
    }
}
