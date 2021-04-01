using ExampleApp.Identity;
using Microsoft.AspNetCore.Identity;
using Microsoft.AspNetCore.Mvc;
using Microsoft.AspNetCore.Mvc.RazorPages;
using System.Collections.Generic;
using System.Linq;
using System.Threading.Tasks;

namespace ExampleApp.Pages.Store {

    public class FindUserModel : PageModel {

        public FindUserModel(UserManager<AppUser> userMgr) {
            UserManager = userMgr;
        }

        public UserManager<AppUser> UserManager { get; set; }

        public IEnumerable<AppUser> Users { get; set; }
            = Enumerable.Empty<AppUser>();

        [BindProperty(SupportsGet = true)]
        public string Searchname { get; set; }

        public async Task OnGet() {
            if (UserManager.SupportsQueryableUsers) {
                string normalizedName =
                    UserManager.NormalizeName(Searchname ?? string.Empty);
                Users = string.IsNullOrEmpty(Searchname)
                    ? UserManager.Users.OrderBy(u => u.UserName)
                    : UserManager.Users.Where(user => user.Id == Searchname ||
                        user.NormalizedUserName.Contains(normalizedName))
                        .OrderBy(u => u.UserName);
            } else if (Searchname != null) {
                AppUser nameUser = await UserManager.FindByNameAsync(Searchname);
                if (nameUser != null) {
                    Users = Users.Append(nameUser);
                }
                AppUser idUser = await UserManager.FindByIdAsync(Searchname);
                if (idUser != null) {
                    Users = Users.Append(idUser);
                }
            }
        }

        public async Task<IActionResult> OnPostDelete(string id) {
            AppUser user = await UserManager.FindByIdAsync(id);
            if (user != null) {
                await UserManager.DeleteAsync(user);
            }
            return RedirectToPage();
        }
    }
}
