using Microsoft.AspNetCore.Identity;
using Microsoft.AspNetCore.Mvc;
using System.Collections.Generic;
using System.Linq;

namespace IdentityApp.Pages.Identity.Admin {

    public class SelectUserModel : AdminPageModel {

        public SelectUserModel(UserManager<IdentityUser> mgr)
            => UserManager = mgr;

        public UserManager<IdentityUser> UserManager { get; set; }
        public IEnumerable<IdentityUser> Users { get; set; }

        [BindProperty(SupportsGet = true)]
        public string Label { get; set; }

        [BindProperty(SupportsGet = true)]
        public string Callback { get; set; }

        [BindProperty(SupportsGet = true)]
        public string Filter { get; set; }

        public void OnGet() {
            Users = UserManager.Users
                .Where(u => Filter == null || u.Email.Contains(Filter))
                .OrderBy(u => u.Email).ToList();
        }

        public IActionResult OnPost() => RedirectToPage(new { Filter, Callback });
    }
}
