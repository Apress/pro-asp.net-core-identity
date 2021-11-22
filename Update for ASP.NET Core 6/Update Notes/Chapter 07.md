# Changes for Chapter 7

## The changes required in this chapter are for null state analysis and the introduction of the minimal API for configuring ASP.NET Core applications.
***

Use the following content for `Listing 7-3`:

    @{ 
        string theme = ViewData["theme"] as string ?? "primary";
        bool showNav = ViewData["showNav"] as bool? ?? true;
        string navPartial = ViewData["navPartial"] as string ?? "_Workflows";
        string workflow = ViewData["workflow"] as string ?? string.Empty;
        string banner =  ViewData["banner"] as string ?? "User Dashboard";
        bool showHeader = ViewData["showHeader"] as bool? ?? true;
    }

    <!DOCTYPE html>
    <html>
    <head>
        <meta name="viewport" content="width=device-width" />
        <title>Identity App</title>
        <link href="/lib/twitter-bootstrap/css/bootstrap.min.css" rel="stylesheet" />
    </head>
    <body>
        @if (showHeader) {
            <nav class="navbar navbar-dark bg-@theme">
                <a class="navbar-brand text-white">IdentityApp</a>
                <div class="text-white"><partial name="_LoginPartial" /></div>        
            </nav>
        }
        <h4 class="bg-@theme text-center text-white p-2">@banner</h4>
        <div class="my-2">
            <div class="container-fluid">
                <div class="row">
                    @if (showNav) {
                        <div class="col-auto">
                            <partial name="@navPartial" model="@((workflow, theme))" />
                        </div>
                    }
                    <div class="col">
                        @RenderBody()
                    </div>
                </div>
            </div>
        </div>
    </body>
    </html>

***

Use the following code for `Listing 7-11`:

    namespace IdentityApp.Pages.Identity {

        public class IndexModel : UserPageModel {

            public string Email { get; set; } = string.Empty;
            public string Phone { get; set; } = string.Empty;
        }
    }

***

Use the following content for `Listing 7-14`:

    <nav class="nav">
        @if (User.Identity?.IsAuthenticated == true) { 
            <a asp-page="/Identity/Index" class="nav-link bg-secondary text-white">
                    @User.Identity.Name
            </a>
            <a asp-area="Identity" asp-page="/Account/Logout" 
                class="nav-link bg-secondary text-white">
                    Logout
            </a>
        } else {
            <a asp-area="Identity" asp-page="/Account/Login" 
                    class="nav-link bg-secondary text-white">
                Login/Register
            </a>
        }
    </nav>

***

Use the following content for `Listing 7-20`:

    @page "{label?}/{callback?}"
    @model IdentityApp.Pages.Identity.Admin.SelectUserModel
    @{  
        ViewBag.Workflow = Model.Callback ?? Model.Label ?? "List";
    }

    <form method="post" class="my-2">
        <div class="form-row">
            <div class="col">
                <div class="input-group">
                    <input asp-for="Filter" class="form-control" />
                </div>
            </div>
            <div class="col-auto">
                <button class="btn btn-secondary">Filter</button>
            </div>        
        </div>
    </form>

    <table class="table table-sm table-striped table-bordered">
        <thead>
            <tr>
                <th>User</th>
                @if (!string.IsNullOrEmpty(Model.Callback)) {
                    <th/>
                }
            </tr>
        </thead>
        <tbody>
            @if (Model.Users?.Count() == 0) {
                <tr><td colspan="2">No matches</td></tr>
            } else {
                @foreach (IdentityUser user in Model.Users ?? Enumerable.Empty<IdentityUser>()) {
                    <tr>
                        <td>@user.Email</td>
                        @if (!string.IsNullOrEmpty(Model.Callback)) {
                            <td class="text-center">
                                <a asp-page="@Model.Callback" 
                                asp-route-id="@user.Id" 
                                class="btn btn-sm btn-secondary">
                                    @Model.Callback
                                </a>
                            </td>
                        }
                    </tr>
                }
            }
        </tbody>
    </table>

    @if (!string.IsNullOrEmpty(Model.Callback)) {
        <a asp-page="Dashboard" class="btn btn-secondary">Cancel</a>
    }

***

Use the following code for `Listing 7-21`:

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

***

Use the following code for `Listing 7-24`:

    using Microsoft.AspNetCore.Identity;
    using Microsoft.AspNetCore.Mvc;
    using System.Collections.Generic;
    using System.Linq;
    using System.Threading.Tasks;

    namespace IdentityApp.Pages.Identity.Admin {

        public class ViewModel : AdminPageModel {

            public ViewModel(UserManager<IdentityUser> mgr) => UserManager = mgr;

            public UserManager<IdentityUser> UserManager { get; set; }

            public IdentityUser IdentityUser { get; set; } = new();

            [BindProperty(SupportsGet = true)]
            public string Id { get; set; } = string.Empty;

            public IEnumerable<string> PropertyNames
                => typeof(IdentityUser).GetProperties()
                    .Select(prop => prop.Name);

            public string? GetValue(string name) =>
                typeof(IdentityUser).GetProperty(name)?
                    .GetValue(IdentityUser)?.ToString();

            public async Task<IActionResult> OnGetAsync() {
                if (string.IsNullOrEmpty(Id)) {
                    return RedirectToPage("Selectuser",
                        new { Label = "View User", Callback = "View" });
                }
                IdentityUser = await UserManager.FindByIdAsync(Id);
                return Page();
            }
        }
    }

***

Use the following code for `Listing 7-27`:

    using Microsoft.AspNetCore.Identity;
    using Microsoft.AspNetCore.Mvc;
    using System.ComponentModel.DataAnnotations;
    using System.Threading.Tasks;

    namespace IdentityApp.Pages.Identity.Admin {

        public class EditBindingTarget {
            [Required]
            public string Username { get; set; } = string.Empty;
            [Required]
            [EmailAddress]
            public string Email { get; set; } = string.Empty;
            [Phone]
            public string? PhoneNumber { get; set; }
        }

        public class EditModel : AdminPageModel {

            public EditModel(UserManager<IdentityUser> mgr) => UserManager = mgr;

            public UserManager<IdentityUser> UserManager { get; set; }

            public IdentityUser IdentityUser { get; set; } = new();

            [BindProperty(SupportsGet = true)]
            public string Id { get; set; } = string.Empty;

            public async Task<IActionResult> OnGetAsync() {
                if (string.IsNullOrEmpty(Id)) {
                    return RedirectToPage("Selectuser",
                        new { Label = "Edit User", Callback = "Edit" });
                }
                IdentityUser = await UserManager.FindByIdAsync(Id);
                return Page();
            }

            public async Task<IActionResult> OnPostAsync(
                    [FromForm(Name = "IdentityUser")] EditBindingTarget userData) {
                if (!string.IsNullOrEmpty(Id) && ModelState.IsValid) {
                    IdentityUser user = await UserManager.FindByIdAsync(Id);
                    if (user != null) {
                        user.UserName = userData.Username;
                        user.Email = userData.Email;
                        user.EmailConfirmed = true;
                        if (!string.IsNullOrEmpty(userData.PhoneNumber)) {
                            user.PhoneNumber = userData.PhoneNumber;
                        }
                        IdentityResult result = await UserManager.UpdateAsync(user);
                        if (result.Process(ModelState)) {
                            return RedirectToPage();
                        }
                    }
                }
                IdentityUser = await UserManager.FindByIdAsync(Id);
                return Page();
            }
        }
    }

***

Use the following code for `Listing 7-30`:

    ...
    public async Task<IActionResult> OnPostAsync(
            [FromForm(Name = "IdentityUser")] EditBindingTarget userData) {
        if (!string.IsNullOrEmpty(Id) && ModelState.IsValid) {
            IdentityUser user = await UserManager.FindByIdAsync(Id);
            if (user != null) {
                user.UserName = userData.Email;
                user.Email = userData.Email;
                user.EmailConfirmed = true;
                if (!string.IsNullOrEmpty(userData.PhoneNumber)) {
                    user.PhoneNumber = userData.PhoneNumber;
                }
                IdentityResult result = await UserManager.UpdateAsync(user);
                if (result.Process(ModelState)) {
                    return RedirectToPage();
                }
            }
        }
        IdentityUser = await UserManager.FindByIdAsync(Id);
        return Page();
    }
    ...

***

Use the following content for `Listing 7-31`:

    @page
    @model IdentityApp.Pages.Identity.Admin.FeaturesModel
    @inject UserManager<IdentityUser> UserManager
    @{ 
        ViewBag.Workflow = "Features";
    }

    <table class="table table-sm table-striped table-bordered">
        <thead><tr><th>Property</th><th>Supported</th></tr></thead>
        <tbody>
            @foreach ((string prop, string? val) in Model.Features ?? Enumerable.Empty<(string, string?)>() ) {
                <tr>
                    <td>@prop</td>
                    <td class="@(val == "True" ? "bg-success" : "bg-danger") text-white">
                        @val
                    </td>
                </tr>
            }
        </tbody>
    </table>

***

Use the following code for `Listing 7-32`:

    using Microsoft.AspNetCore.Identity;

    namespace IdentityApp.Pages.Identity.Admin {
        public class FeaturesModel : AdminPageModel {

            public FeaturesModel(UserManager<IdentityUser> mgr)
                => UserManager = mgr;

            public UserManager<IdentityUser> UserManager { get; set; }

            public IEnumerable<(string, string?)>? Features { get; set; } 

            public void OnGet() {
                Features = UserManager.GetType().GetProperties()?
                    .Where(prop => prop.Name.StartsWith("Supports"))?
                    .OrderBy(p => p.Name).Select(prop => (prop.Name, prop.GetValue(UserManager)?.ToString()));
            }
        }
    }

***

For `Listing 7-34`, apply the following code to the `Program.cs` file:

    ...
    services.AddIdentity<IdentityUser, IdentityRole>(opts => {
        opts.Password.RequiredLength = 8;
        opts.Password.RequireDigit = false;
        opts.Password.RequireLowercase = false;
        opts.Password.RequireUppercase = false;
        opts.Password.RequireNonAlphanumeric = false;
        opts.SignIn.RequireConfirmedAccount = true;
    }).AddEntityFrameworkStores<IdentityDbContext>();
    ...

***