# Changes for Chapter 10

## The changes required in this chapter are for null state analysis and the introduction of the minimal API for configuring ASP.NET Core applications.
***

Use the following code for `Listing 10-4`:

    using Microsoft.AspNetCore.Identity;
    using Microsoft.AspNetCore.Mvc;
    using System.ComponentModel.DataAnnotations;

    namespace IdentityApp.Pages.Identity.Admin {

        public class RolesModel : AdminPageModel {

            public RolesModel(UserManager<IdentityUser> userMgr,
                    RoleManager<IdentityRole> roleMgr) {
                UserManager = userMgr;
                RoleManager = roleMgr;
            }

            [BindProperty(SupportsGet = true)]
            public string? Id { get; set; }

            public UserManager<IdentityUser> UserManager { get; set; }
            public RoleManager<IdentityRole> RoleManager { get; set; }

            public IList<string> CurrentRoles { get; set; } = new List<string>();
            public IList<string> AvailableRoles { get; set; } = new List<string>();

            private async Task SetProperties() {
                IdentityUser user = await UserManager.FindByIdAsync(Id);
                CurrentRoles = await UserManager.GetRolesAsync(user);
                AvailableRoles = RoleManager.Roles.Select(r => r.Name)
                    .Where(r => !CurrentRoles.Contains(r)).ToList();
            }

            public async Task<IActionResult> OnGetAsync() {
                if (string.IsNullOrEmpty(Id)) {
                    return RedirectToPage("Selectuser",
                        new { Label = "Edit Roles", Callback = "Roles" });
                }
                await SetProperties();
                return Page();
            }

            public async Task<IActionResult> OnPostAddToList(string role) {
                IdentityResult result =
                    await RoleManager.CreateAsync(new IdentityRole(role));
                if (result.Process(ModelState)) {
                    return RedirectToPage();
                }
                await SetProperties();
                return Page();
            }

            public async Task<IActionResult> OnPostDeleteFromList(string role) {
                IdentityRole idRole = await RoleManager.FindByNameAsync(role);
                IdentityResult result = await RoleManager.DeleteAsync(idRole);
                if (result.Process(ModelState)) {
                    return RedirectToPage();
                }
                await SetProperties();
                return Page();
            }

            public async Task<IActionResult> OnPostAdd([Required] string role) {
                if (ModelState.IsValid) {
                    IdentityResult result = IdentityResult.Success;
                    if (result.Process(ModelState)) {
                        IdentityUser user = await UserManager.FindByIdAsync(Id);
                        if (!await UserManager.IsInRoleAsync(user, role)) {
                            result = await UserManager.AddToRoleAsync(user, role);
                        }
                        if (result.Process(ModelState)) {
                            return RedirectToPage();
                        }
                    }
                }
                await SetProperties();
                return Page();
            }

            public async Task<IActionResult> OnPostDelete(string role) {
                IdentityUser user = await UserManager.FindByIdAsync(Id);
                if (await UserManager.IsInRoleAsync(user, role)) {
                    await UserManager.RemoveFromRoleAsync(user, role);
                }
                return RedirectToPage();
            }
        }
    }

***

Use the following code for `Listing 10-6`:

    using Microsoft.AspNetCore.Identity;

    namespace IdentityApp {
        public static class DashBoardSeed {

            public static void SeedUserStoreForDashboard(this IApplicationBuilder app) {
                SeedStore(app).GetAwaiter().GetResult();
            }

            private async static Task SeedStore(IApplicationBuilder app) {
                using (var scope = app.ApplicationServices.CreateScope()) {
                    IConfiguration config =
                        scope.ServiceProvider.GetRequiredService<IConfiguration>();
                    UserManager<IdentityUser> userManager =
                        scope.ServiceProvider.GetRequiredService<UserManager<IdentityUser>>();
                    RoleManager<IdentityRole> roleManager =
                        scope.ServiceProvider.GetRequiredService<RoleManager<IdentityRole>>();

                    string roleName = config["Dashboard:Role"] ?? "Dashboard";
                    string userName = config["Dashboard:User"] ?? "admin@example.com";
                    string password = config["Dashboard:Password"] ?? "mysecret";

                    if (!await roleManager.RoleExistsAsync(roleName)) {
                        await roleManager.CreateAsync(new IdentityRole(roleName));
                    }
                    IdentityUser dashboardUser =
                        await userManager.FindByEmailAsync(userName);
                    if (dashboardUser == null) {
                        dashboardUser = new IdentityUser {
                            UserName = userName,
                            Email = userName,
                            EmailConfirmed = true
                        };
                        await userManager.CreateAsync(dashboardUser);
                        dashboardUser = await userManager.FindByEmailAsync(userName);
                        await userManager.AddPasswordAsync(dashboardUser, password);
                    }
                    if (!await userManager.IsInRoleAsync(dashboardUser, roleName)) {
                        await userManager.AddToRoleAsync(dashboardUser, roleName);
                    }
                }
            }
        }
    }

***


Ignore `Listing 10-7` and configure the application using the following code in the `Program.cs` file:

    using Microsoft.EntityFrameworkCore;
    using IdentityApp.Models;
    using Microsoft.AspNetCore.Identity;
    using Microsoft.AspNetCore.Identity.EntityFrameworkCore;
    using Microsoft.AspNetCore.Identity.UI.Services;
    using IdentityApp.Services;
    using IdentityApp;

    var builder = WebApplication.CreateBuilder(args);

    builder.Services.AddControllersWithViews();
    builder.Services.AddRazorPages();
    builder.Services.AddDbContext<ProductDbContext>(opts => {
        opts.UseSqlServer(
            builder.Configuration["ConnectionStrings:AppDataConnection"]);
    });

    builder.Services.AddHttpsRedirection(opts => {
        opts.HttpsPort = 44350;
    });

    builder.Services.AddDbContext<IdentityDbContext>(opts => {
        opts.UseSqlServer(
            builder.Configuration["ConnectionStrings:IdentityConnection"],
            opts => opts.MigrationsAssembly("IdentityApp")
        );
    });

    builder.Services.AddIdentity<IdentityUser, IdentityRole>(opts => {
        opts.Password.RequiredLength = 8;
        opts.Password.RequireDigit = false;
        opts.Password.RequireLowercase = false;
        opts.Password.RequireUppercase = false;
        opts.Password.RequireNonAlphanumeric = false;
        opts.SignIn.RequireConfirmedAccount = true;
    }).AddEntityFrameworkStores<IdentityDbContext>()
        .AddDefaultTokenProviders();

    builder.Services.AddScoped<TokenUrlEncoderService>();
    builder.Services.AddScoped<IdentityEmailService>();

    builder.Services.AddScoped<IEmailSender, ConsoleEmailSender>();

    builder.Services.AddAuthentication()
        .AddFacebook(opts => {
            opts.AppId = builder. Configuration["Facebook:AppId"];
            opts.AppSecret = builder.Configuration["Facebook:AppSecret"];
        })
        .AddGoogle(opts => {
            opts.ClientId = builder.Configuration["Google:ClientId"];
            opts.ClientSecret = builder.Configuration["Google:ClientSecret"];
        })
        .AddTwitter(opts => {
            opts.ConsumerKey = builder.Configuration["Twitter:ApiKey"];
            opts.ConsumerSecret = builder.Configuration["Twitter:ApiSecret"];
        });

    builder.Services.ConfigureApplicationCookie(opts => {
        opts.LoginPath = "/Identity/SignIn";
        opts.LogoutPath = "/Identity/SignOut";
        opts.AccessDeniedPath = "/Identity/Forbidden";
    });

    builder.Services.Configure<SecurityStampValidatorOptions>(opts => {
        opts.ValidationInterval = System.TimeSpan.FromMinutes(1);
    });

    var app = builder.Build();

    app.UseHttpsRedirection();
    app.UseStaticFiles();

    app.UseAuthentication();
    app.UseAuthorization();

    app.MapDefaultControllerRoute();
    app.MapRazorPages();

    app.SeedUserStoreForDashboard();

    app.Run();

***

Use the following code for `Listing 10-8`:

    using Microsoft.AspNetCore.Identity;
    using Microsoft.AspNetCore.Mvc;
    using System.ComponentModel.DataAnnotations;

    namespace IdentityApp.Pages.Identity.Admin {

        public class RolesModel : AdminPageModel {

            public RolesModel(UserManager<IdentityUser> userMgr,
                    RoleManager<IdentityRole> roleMgr,
                    IConfiguration config) {
                UserManager = userMgr;
                RoleManager = roleMgr;
                DashboardRole = config["Dashboard:Role"] ?? "Dashboard";
            }

            [BindProperty(SupportsGet = true)]
            public string? Id { get; set; }

            public UserManager<IdentityUser> UserManager { get; set; }
            public RoleManager<IdentityRole> RoleManager { get; set; }

            public IList<string> CurrentRoles { get; set; } = new List<string>();
            public IList<string> AvailableRoles { get; set; } = new List<string>();

            public string DashboardRole { get; }

            private async Task SetProperties() {
                IdentityUser user = await UserManager.FindByIdAsync(Id);
                CurrentRoles = await UserManager.GetRolesAsync(user);
                AvailableRoles = RoleManager.Roles.Select(r => r.Name)
                    .Where(r => !CurrentRoles.Contains(r)).ToList();
            }

            public async Task<IActionResult> OnGetAsync() {
                if (string.IsNullOrEmpty(Id)) {
                    return RedirectToPage("Selectuser",
                        new { Label = "Edit Roles", Callback = "Roles" });
                }
                await SetProperties();
                return Page();
            }

            public async Task<IActionResult> OnPostAddToList(string role) {
                IdentityResult result =
                    await RoleManager.CreateAsync(new IdentityRole(role));
                if (result.Process(ModelState)) {
                    return RedirectToPage();
                }
                await SetProperties();
                return Page();
            }

            public async Task<IActionResult> OnPostDeleteFromList(string role) {
                IdentityRole idRole = await RoleManager.FindByNameAsync(role);
                IdentityResult result = await RoleManager.DeleteAsync(idRole);
                if (result.Process(ModelState)) {
                    return RedirectToPage();
                }
                await SetProperties();
                return Page();
            }

            public async Task<IActionResult> OnPostAdd([Required] string role) {
                if (ModelState.IsValid) {
                    IdentityResult result = IdentityResult.Success;
                    if (result.Process(ModelState)) {
                        IdentityUser user = await UserManager.FindByIdAsync(Id);
                        if (!await UserManager.IsInRoleAsync(user, role)) {
                            result = await UserManager.AddToRoleAsync(user, role);
                        }
                        if (result.Process(ModelState)) {
                            return RedirectToPage();
                        }
                    }
                }
                await SetProperties();
                return Page();
            }

            public async Task<IActionResult> OnPostDelete(string role) {
                IdentityUser user = await UserManager.FindByIdAsync(Id);
                if (await UserManager.IsInRoleAsync(user, role)) {
                    await UserManager.RemoveFromRoleAsync(user, role);
                }
                return RedirectToPage();
            }
        }
    }

***

Use the following code for `Listing 10-11`:

    using Microsoft.AspNetCore.Mvc.RazorPages;
    using Microsoft.AspNetCore.Identity;
    using Microsoft.AspNetCore.Mvc;
    using System.Threading.Tasks;
    using System.Linq;
    using Microsoft.Extensions.Configuration;

    namespace IdentityApp.Pages.Identity.Admin {

        public class DashboardModel : AdminPageModel {

            public DashboardModel(UserManager<IdentityUser> userMgr,
                    IConfiguration configuration) {
                UserManager = userMgr;
                DashboardRole = configuration["Dashboard:Role"] ?? "Dashboard";
            }

            public UserManager<IdentityUser> UserManager { get; set; }

            public string DashboardRole { get; set; }

            public int UsersCount { get; set; } = 0;
            public int UsersUnconfirmed { get; set; } = 0;
            public int UsersLockedout { get; set; } = 0;
            public int UsersTwoFactor { get; set; } = 0;

            private readonly string[] emails = {
                "alice@example.com", "bob@example.com", "charlie@example.com"
            };

            public void OnGet() {
                UsersCount = UserManager.Users.Count();
                UsersUnconfirmed = UserManager.Users
                    .Where(u => !u.EmailConfirmed).Count();
                UsersLockedout = UserManager.Users
                    .Where(u => u.LockoutEnabled && u.LockoutEnd > System.DateTimeOffset.Now)
                    .Count();
            }

            public async Task<IActionResult> OnPostAsync() {
                foreach (IdentityUser existingUser in UserManager.Users.ToList()) {
                    if (emails.Contains(existingUser.Email) ||
                        !await UserManager.IsInRoleAsync(existingUser, DashboardRole)) {
                        IdentityResult result = await UserManager.DeleteAsync(existingUser);
                        result.Process(ModelState);
                    }
                }
                foreach (string email in emails) {
                    IdentityUser userObject = new IdentityUser {
                        UserName = email,
                        Email = email,
                        EmailConfirmed = true
                    };
                    IdentityResult result = await UserManager.CreateAsync(userObject);
                    if (result.Process(ModelState)) {
                        result = await UserManager.AddPasswordAsync(userObject, "mysecret");
                        result.Process(ModelState);
                    }
                }
                if (ModelState.IsValid) {
                    return RedirectToPage();
                }
                return Page();
            }
        }
    }

***

Use the following content for `Listing 10-12`:

    @inject Microsoft.Extensions.Configuration.IConfiguration Configuration
    @{ 
        string dashboardRole = Configuration["Dashboard:Role"] ?? "Dashboard";
    }
    <nav class="nav">
        @if (User.Identity?.IsAuthenticated == true) {
            @if (User.IsInRole(dashboardRole)) {
                <a asp-page="/Identity/Admin/Dashboard" 
                    class="nav-link bg-secondary text-white">
                        @User.Identity?.Name
                </a>
            } else {
                <a asp-page="/Identity/Index" class="nav-link bg-secondary text-white">
                        @User.Identity?.Name
                </a>
            }
            <a asp-page="/Identity/SignOut" class="nav-link bg-secondary text-white">
                Sign Out
            </a>
        } else {
            <a asp-page="/Identity/SignIn" class="nav-link bg-secondary text-white">
                Sign In/Register
            </a>
        }
    </nav>

***

Use the following code for `Listing 10-14`:

    using System.Collections.Generic;
    using System.Linq;
    using System.Security.Claims;

    namespace IdentityApp.Models {

        public static class ApplicationClaimTypes {
            public const string Country = ClaimTypes.Country;
            public const string SecurityClearance = "SecurityClearance";

            public static string GetDisplayName(this Claim claim)
                => GetDisplayName(claim.Type);

            public static string GetDisplayName(string claimType)
                => typeof(ClaimTypes).GetFields().Where(field =>
                        field.GetRawConstantValue()?.ToString() == claimType)
                            .Select(field => field.Name)
                            .FirstOrDefault() ?? claimType;

            public static IEnumerable<(string type, string display)> AppClaimTypes
                = new[] { Country, SecurityClearance }.Select(c =>
                    (c, GetDisplayName(c)));
        }
    }

***
Use the following code for `Listing 10-16`:

    using System.Security.Claims;
    using Microsoft.AspNetCore.Mvc;
    using Microsoft.AspNetCore.Identity;
    using System.ComponentModel.DataAnnotations;

    namespace IdentityApp.Pages.Identity.Admin {

        public class ClaimsModel : AdminPageModel {

            public ClaimsModel(UserManager<IdentityUser> mgr)
                => UserManager = mgr;

            public UserManager<IdentityUser> UserManager { get; set; }

            [BindProperty(SupportsGet = true)]
            public string Id { get; set; } = String.Empty;

            public IEnumerable<Claim> Claims { get; set; } = Enumerable.Empty<Claim>();

            public async Task<IActionResult> OnGetAsync() {
                if (string.IsNullOrEmpty(Id)) {
                    return RedirectToPage("Selectuser",
                        new { Label = "Manage Claims", Callback = "Claims" });
                }
                IdentityUser user = await UserManager.FindByIdAsync(Id);
                Claims = await UserManager.GetClaimsAsync(user);
                return Page();
            }

            public async Task<IActionResult> OnPostAsync([Required] string task,
                    [Required] string type, [Required] string value, string? oldValue) {
                IdentityUser user = await UserManager.FindByIdAsync(Id);
                Claims = await UserManager.GetClaimsAsync(user);
                if (ModelState.IsValid) {
                    Claim claim = new Claim(type, value);
                    IdentityResult result = IdentityResult.Success;
                    switch (task) {
                        case "add":
                            result = await UserManager.AddClaimAsync(user, claim);
                            break;
                        case "change":
                            result = await UserManager.ReplaceClaimAsync(user,
                                new Claim(type, oldValue ?? ""), claim);
                            break;
                        case "delete":
                            result = await UserManager.RemoveClaimAsync(user, claim);
                            break;
                    };
                    if (result.Process(ModelState)) {
                        return RedirectToPage();
                    }
                }
                return Page();
            }
        }
    }

***

Use the following code for `Listing 10-19`:

    using Microsoft.AspNetCore.Identity;
    using Microsoft.AspNetCore.Mvc;
    using System.Security.Claims;
    using System.Threading.Tasks;

    namespace IdentityApp.Pages.Identity.Admin {

        public class ViewClaimsPrincipalModel : AdminPageModel {

            public ViewClaimsPrincipalModel(UserManager<IdentityUser> usrMgr,
                    SignInManager<IdentityUser> signMgr) {
                UserManager = usrMgr;
                SignInManager = signMgr;
            }

            [BindProperty(SupportsGet = true)]
            public string? Id { get; set; }

            [BindProperty(SupportsGet = true)]
            public string? Callback { get; set; }

            public UserManager<IdentityUser> UserManager { get; set; }
            public SignInManager<IdentityUser> SignInManager { get; set; }

            public ClaimsPrincipal Principal { get; set; } = new();

            public async Task<IActionResult> OnGetAsync() {
                if (string.IsNullOrEmpty(Id)) {
                    return RedirectToPage("Selectuser",
                        new {
                            Label = "View ClaimsPrincipal",
                            Callback = "ClaimsPrincipal"
                        });
                }
                IdentityUser user = await UserManager.FindByIdAsync(Id);
                Principal = await SignInManager.CreateUserPrincipalAsync(user);
                return Page();
            }
        }
    }

***