using Microsoft.AspNetCore.Identity;
using Microsoft.AspNetCore.Mvc;
using System.Collections.Generic;
using System.Linq;

namespace IdentityApp.Pages.Identity.Admin {

    public class SelectUserModel : AdminPageModel {

        public SelectUserModel(UserManager<IdentityUser> mgr)
            => UserManager = mgr;

        public UserManager<IdentityUser>? UserManager { get; set; } 
        public IEnumerable<IdentityUser>? Users { get; set; }

        [BindProperty(SupportsGet = true)]
        public string Label { get; set; } = String.Empty;

        [BindProperty(SupportsGet = true)]
        public string Callback { get; set; } = String.Empty;

        [BindProperty(SupportsGet = true)]
        public string Filter { get; set; } = String.Empty;

        public void OnGet() {
            Users = UserManager?.Users
                .Where(u => Filter == null || u.Email.Contains(Filter))
                .OrderBy(u => u.Email).ToList();
        }

        public IActionResult OnPost() => RedirectToPage(new { Filter, Callback });
    }
}
