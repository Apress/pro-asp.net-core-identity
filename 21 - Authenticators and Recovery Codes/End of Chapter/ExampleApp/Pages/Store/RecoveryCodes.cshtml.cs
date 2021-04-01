using ExampleApp.Identity;
using ExampleApp.Identity.Store;
using Microsoft.AspNetCore.Identity;
using Microsoft.AspNetCore.Mvc;
using Microsoft.AspNetCore.Mvc.RazorPages;
using System.Collections.Generic;
using System.Linq;
using System.Threading.Tasks;

namespace ExampleApp.Pages.Store {

    public class RecoveryCodesModel : PageModel {

        public RecoveryCodesModel(UserManager<AppUser> manager,
                IUserStore<AppUser> store) {
            UserManager = manager;
            UserStore = store;
        }

        public UserManager<AppUser> UserManager { get; set; }
        public IUserStore<AppUser> UserStore { get; set; }

        public AppUser AppUser { get; set; }

        public RecoveryCode[] Codes { get; set; }
        public int RemainingCodes { get; set; }

        public async Task OnGetAsync(string id) {
            AppUser = await UserManager.FindByIdAsync(id);
            if (AppUser != null) {
                Codes = (await GetCodes()).OrderBy(c => c.Code).ToArray();
                RemainingCodes = await UserManager.CountRecoveryCodesAsync(AppUser);
            }
        }

        public async Task<IActionResult> OnPostAsync(string id) {
            AppUser = await UserManager.FindByIdAsync(id);
            await UserManager.GenerateNewTwoFactorRecoveryCodesAsync(AppUser, 10);
            return RedirectToPage();
        }

        private async Task<IEnumerable<RecoveryCode>> GetCodes() {
            if (UserStore is IReadableUserTwoFactorRecoveryCodeStore) {
                return await (UserStore as
                    IReadableUserTwoFactorRecoveryCodeStore).GetCodesAsync(AppUser);
            }
            return Enumerable.Empty<RecoveryCode>();
        }
    }
}
