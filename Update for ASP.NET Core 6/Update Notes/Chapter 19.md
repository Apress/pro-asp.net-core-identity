# Changes for Chapter 19

## Not all of the Identity API methods have  been correctly annotated for null state analysis, which requires the use of the #pragma directive in some listings. 
***

Use the following commands for `Listing 19-2`:

    using System;

    namespace ExampleApp.Identity {

        public class AppRole {

            public string Id { get; set; } = Guid.NewGuid().ToString();

            public string Name { get; set; } = String.Empty;

            public string NormalizedName { get; set; } = String.Empty;
        }
    }

***

Use the following commands for `Listing 19-3`:

    using Microsoft.AspNetCore.Identity;
    using System.Collections.Concurrent;
    using System.Threading;
    using System.Threading.Tasks;

    namespace ExampleApp.Identity.Store {
        public partial class RoleStore : IRoleStore<AppRole> {
            private ConcurrentDictionary<string, AppRole> roles
                = new ConcurrentDictionary<string, AppRole>();

            public Task<IdentityResult> CreateAsync(AppRole role,
                    CancellationToken token) {
                if (!roles.ContainsKey(role.Id) && roles.TryAdd(role.Id, role)) {
                    return Task.FromResult(IdentityResult.Success);
                }
                return Task.FromResult(Error);
            }

            public Task<IdentityResult> DeleteAsync(AppRole role,
                    CancellationToken token) {
                AppRole? outRole;
                if (roles.ContainsKey(role.Id) && roles.TryRemove(role.Id, out outRole)) {
                    return Task.FromResult(IdentityResult.Success);
                }
                return Task.FromResult(Error);
            }

            public Task<IdentityResult> UpdateAsync(AppRole role,
                    CancellationToken token) {
                if (roles.ContainsKey(role.Id)) {
                    roles[role.Id].UpdateFrom(role);
                    return Task.FromResult(IdentityResult.Success);
                }
                return Task.FromResult(Error);
            }

            public void Dispose() {
                // do nothing
            }

            private IdentityResult Error => IdentityResult.Failed(new IdentityError {
                Code = "StorageFailure",
                Description = "Role Store Error"
            });
        }
    }

***

Use the following commands for `Listing 19-5`:

    #pragma warning disable CS8619 

    namespace ExampleApp.Identity.Store {

        public partial class RoleStore {

            public Task<AppRole> FindByIdAsync(string id, CancellationToken token)
                => Task.FromResult(roles.ContainsKey(id) ? roles[id].Clone() : null);

            public Task<AppRole> FindByNameAsync(string name, CancellationToken token)
                => Task.FromResult(roles.Values.FirstOrDefault(r => r.NormalizedName ==
                    name)?.Clone());
        }
    }

***

Use the following commands for `Listing 19-6`:

    using Microsoft.AspNetCore.Identity;

    #pragma warning disable CS8619 

    namespace ExampleApp.Identity.Store {

        public partial class RoleStore : IQueryableRoleStore<AppRole> {

            public Task<AppRole> FindByIdAsync(string id, CancellationToken token)
                => Task.FromResult(roles.ContainsKey(id) ? roles[id].Clone() : null);

            public Task<AppRole> FindByNameAsync(string name, CancellationToken token)
                => Task.FromResult(roles.Values.FirstOrDefault(r => r.NormalizedName ==
                    name)?.Clone());

            public IQueryable<AppRole> Roles =>
                roles.Values.Select(role => role.Clone()).AsQueryable<AppRole>();

        }
    }

***

Ignore `Listing 19-8` and configure the application using the following code in the `Program.cs` file:

    using ExampleApp.Custom;
    using Microsoft.AspNetCore.Authentication.Cookies;
    using Microsoft.AspNetCore.Authorization;
    using Microsoft.AspNetCore.Identity;
    using ExampleApp.Identity;
    using ExampleApp.Identity.Store;
    using ExampleApp.Services;

    var builder = WebApplication.CreateBuilder(args);

    builder.Services.AddSingleton<ILookupNormalizer, Normalizer>();
    builder.Services.AddSingleton<IUserStore<AppUser>, UserStore>();
    builder.Services.AddIdentityCore<AppUser>();
    builder.Services.AddSingleton<IUserValidator<AppUser>, EmailValidator>();
    builder.Services.AddSingleton<IPasswordValidator<AppUser>, PasswordValidator>();
    builder.Services.AddSingleton<IEmailSender, ConsoleEmailSender>();
    builder.Services.AddSingleton<ISMSSender, ConsoleSMSSender>();
    //builder.Services.AddSingleton<IUserClaimsPrincipalFactory<AppUser>,
    //    AppUserClaimsPrincipalFactory>();
    builder.Services.AddSingleton<IPasswordHasher<AppUser>, SimplePasswordHasher>();
    builder.Services.AddSingleton<IRoleStore<AppRole>, RoleStore>();
    builder.Services.AddSingleton<IUserClaimsPrincipalFactory<AppUser>,
        AppUserClaimsPrincipalFactory>();

    builder.Services.AddIdentityCore<AppUser>(opts => {
        opts.Tokens.EmailConfirmationTokenProvider = "SimpleEmail";
        opts.Tokens.ChangeEmailTokenProvider = "SimpleEmail";
        opts.Tokens.PasswordResetTokenProvider = TokenOptions.DefaultPhoneProvider;
        opts.Password.RequireNonAlphanumeric = false;
        opts.Password.RequireLowercase = false;
        opts.Password.RequireUppercase = false;
        opts.Password.RequireDigit = false;
        opts.Password.RequiredLength = 8;
    })
    .AddTokenProvider<EmailConfirmationTokenGenerator>("SimpleEmail")
    .AddTokenProvider<PhoneConfirmationTokenGenerator>(
        TokenOptions.DefaultPhoneProvider)
    .AddSignInManager()
    .AddRoles<AppRole>();

    builder.Services.AddAuthentication(opts => {
        opts.DefaultScheme = IdentityConstants.ApplicationScheme;
    }).AddCookie(IdentityConstants.ApplicationScheme, opts => {
        opts.LoginPath = "/signin";
        opts.AccessDeniedPath = "/signin/403";
    });
    builder.Services.AddAuthorization(opts => {
        AuthorizationPolicies.AddPolicies(opts);
    });
    builder.Services.AddRazorPages();
    builder.Services.AddControllersWithViews();

    var app = builder.Build();

    app.UseStaticFiles();

    app.UseAuthentication();

    app.UseMiddleware<RoleMemberships>();
    app.UseAuthorization();

    app.UseAuthorization();

    app.MapRazorPages();
    app.MapDefaultControllerRoute();
    app.MapFallbackToPage("/Secret");

    app.Run();

    ***

Ignore `Listing 19-12` and configure the application using the following code in the `Program.cs` file:    

    using ExampleApp.Custom;
    using Microsoft.AspNetCore.Authentication.Cookies;
    using Microsoft.AspNetCore.Authorization;
    using Microsoft.AspNetCore.Identity;
    using ExampleApp.Identity;
    using ExampleApp.Identity.Store;
    using ExampleApp.Services;

    var builder = WebApplication.CreateBuilder(args);

    builder.Services.AddSingleton<ILookupNormalizer, Normalizer>();
    builder.Services.AddSingleton<IUserStore<AppUser>, UserStore>();
    builder.Services.AddIdentityCore<AppUser>();
    builder.Services.AddSingleton<IUserValidator<AppUser>, EmailValidator>();
    builder.Services.AddSingleton<IPasswordValidator<AppUser>, PasswordValidator>();
    builder.Services.AddSingleton<IEmailSender, ConsoleEmailSender>();
    builder.Services.AddSingleton<ISMSSender, ConsoleSMSSender>();
    //builder.Services.AddSingleton<IUserClaimsPrincipalFactory<AppUser>,
    //    AppUserClaimsPrincipalFactory>();
    builder.Services.AddSingleton<IPasswordHasher<AppUser>, SimplePasswordHasher>();
    builder.Services.AddSingleton<IRoleStore<AppRole>, RoleStore>();
    builder.Services.AddSingleton<IUserClaimsPrincipalFactory<AppUser>,
        AppUserClaimsPrincipalFactory>();
    builder.Services.AddSingleton<IRoleValidator<AppRole>, RoleValidator>();

    builder.Services.AddIdentityCore<AppUser>(opts => {
        opts.Tokens.EmailConfirmationTokenProvider = "SimpleEmail";
        opts.Tokens.ChangeEmailTokenProvider = "SimpleEmail";
        opts.Tokens.PasswordResetTokenProvider = TokenOptions.DefaultPhoneProvider;
        opts.Password.RequireNonAlphanumeric = false;
        opts.Password.RequireLowercase = false;
        opts.Password.RequireUppercase = false;
        opts.Password.RequireDigit = false;
        opts.Password.RequiredLength = 8;
    })
    .AddTokenProvider<EmailConfirmationTokenGenerator>("SimpleEmail")
    .AddTokenProvider<PhoneConfirmationTokenGenerator>(
        TokenOptions.DefaultPhoneProvider)
    .AddSignInManager()
    .AddRoles<AppRole>();

    builder.Services.AddAuthentication(opts => {
        opts.DefaultScheme = IdentityConstants.ApplicationScheme;
    }).AddCookie(IdentityConstants.ApplicationScheme, opts => {
        opts.LoginPath = "/signin";
        opts.AccessDeniedPath = "/signin/403";
    });
    builder.Services.AddAuthorization(opts => {
        AuthorizationPolicies.AddPolicies(opts);
    });
    builder.Services.AddRazorPages();
    builder.Services.AddControllersWithViews();

    var app = builder.Build();

    app.UseStaticFiles();

    app.UseAuthentication();

    app.UseMiddleware<RoleMemberships>();
    app.UseAuthorization();

    app.UseAuthorization();

    app.MapRazorPages();
    app.MapDefaultControllerRoute();
    app.MapFallbackToPage("/Secret");

    app.Run();

***

Use the following code for `Listing 19-13`:

    using ExampleApp.Identity;
    using Microsoft.AspNetCore.Identity;
    using Microsoft.AspNetCore.Mvc;
    using Microsoft.AspNetCore.Mvc.RazorPages;
    using System.Security.Claims;
    using Microsoft.AspNetCore.Mvc.Rendering;

    #pragma warning disable CS8601
    #pragma warning disable CS8603

    namespace ExampleApp.Pages.Store {

        public class UserRolesModel : PageModel {

            public UserRolesModel(UserManager<AppUser> userManager,
                    RoleManager<AppRole> roleManager) {
                UserManager = userManager;
                RoleManager = roleManager;
            }

            public UserManager<AppUser> UserManager { get; set; }
            public RoleManager<AppRole> RoleManager { get; set; }

            public IEnumerable<string> Roles { get; set; } = Enumerable.Empty<string>();
            public SelectList? AvailableRoles { get; set; } 

            [BindProperty(SupportsGet = true)]
            public string? Id { get; set; }

            public async void OnGet() {
                AppUser user = await GetUser();
                if (user != null) {
                    //Roles = await UserManager.GetRolesAsync(user);
                    Roles = (await UserManager.GetClaimsAsync(user))?
                        .Where(c => c.Type == ClaimTypes.Role).Select(c => c.Value) 
                            ?? Enumerable.Empty<string>();
                    AvailableRoles = new SelectList(RoleManager.Roles
                        .OrderBy(r => r.Name).Select(r => r.Name).Except(Roles));
                }
            }

            public async Task<IActionResult> OnPostAdd(string newRole) {
                //await UserManager.AddToRoleAsync(await GetUser(), newRole);
                await UserManager.AddClaimAsync(await GetUser(),
                    new Claim(ClaimTypes.Role, newRole));
                return RedirectToPage();
            }

            public async Task<IActionResult> OnPostDelete(string role) {
                await UserManager.RemoveFromRoleAsync(await GetUser(), role);
                return RedirectToPage();
            }

            private Task<AppUser> GetUser() => Id == null
                ? null : UserManager.FindByIdAsync(Id);
        }
    }

***

Use the following code for `Listing 19-15`:

    using System.Security.Claims;

    namespace ExampleApp.Identity {

        public class AppRole {

            public string Id { get; set; } = Guid.NewGuid().ToString();

            public string Name { get; set; } = String.Empty;

            public string NormalizedName { get; set; } = String.Empty;

            public IList<Claim> Claims { get; set; } = new List<Claim>();
        }
    }

***

Use the following code for `Listing 19-17`:


    using Microsoft.AspNetCore.Identity;
    using System.Security.Claims;
    using System.Threading.Tasks;

    namespace ExampleApp.Identity {
        public class AppUserClaimsPrincipalFactory : IUserClaimsPrincipalFactory<AppUser> {

            public AppUserClaimsPrincipalFactory(UserManager<AppUser> userManager,
                    RoleManager<AppRole> roleManager) {
                UserManager = userManager;
                RoleManager = roleManager;
            }

            public UserManager<AppUser> UserManager { get; set; }
            public RoleManager<AppRole> RoleManager { get; set; }

            public async Task<ClaimsPrincipal> CreateAsync(AppUser user) {
                ClaimsIdentity identity
                    = new ClaimsIdentity(IdentityConstants.ApplicationScheme);
                identity.AddClaims(new[] {
                    new Claim(ClaimTypes.NameIdentifier, user.Id),
                    new Claim(ClaimTypes.Name, user.UserName),
                    new Claim(ClaimTypes.Email, user.EmailAddress)
                });
                if (!string.IsNullOrEmpty(user.Hobby)) {
                    identity.AddClaim(new Claim("Hobby", user.Hobby));
                }
                if (!string.IsNullOrEmpty(user.FavoriteFood)) {
                    identity.AddClaim(new Claim("FavoriteFood", user.FavoriteFood));
                }
                if (user.Claims != null) {
                    identity.AddClaims(user.Claims);
                }

                if (UserManager.SupportsUserRole && RoleManager.SupportsRoleClaims) {
                    foreach (string roleName in await UserManager.GetRolesAsync(user)) {
                        AppRole role = await RoleManager.FindByNameAsync(roleName);
                        if (role != null && role.Claims != null) {
                            identity.AddClaims(role.Claims);
                        }
                    }
                }

                return new ClaimsPrincipal(identity);
            }
        }
    }

***

Ignore `Listing 19-18` and configure the application using the following code in the `Program.cs` file:

    using ExampleApp.Custom;
    using Microsoft.AspNetCore.Authentication.Cookies;
    using Microsoft.AspNetCore.Authorization;
    using Microsoft.AspNetCore.Identity;
    using ExampleApp.Identity;
    using ExampleApp.Identity.Store;
    using ExampleApp.Services;

    var builder = WebApplication.CreateBuilder(args);

    builder.Services.AddSingleton<ILookupNormalizer, Normalizer>();
    builder.Services.AddSingleton<IUserStore<AppUser>, UserStore>();
    builder.Services.AddIdentityCore<AppUser>();
    builder.Services.AddSingleton<IUserValidator<AppUser>, EmailValidator>();
    builder.Services.AddSingleton<IPasswordValidator<AppUser>, PasswordValidator>();
    builder.Services.AddSingleton<IEmailSender, ConsoleEmailSender>();
    builder.Services.AddSingleton<ISMSSender, ConsoleSMSSender>();
    //builder.Services.AddSingleton<IUserClaimsPrincipalFactory<AppUser>,
    //    AppUserClaimsPrincipalFactory>();
    builder.Services.AddSingleton<IPasswordHasher<AppUser>, SimplePasswordHasher>();
    builder.Services.AddSingleton<IRoleStore<AppRole>, RoleStore>();
    builder.Services.AddScoped<IUserClaimsPrincipalFactory<AppUser>,
        AppUserClaimsPrincipalFactory>();
    builder.Services.AddSingleton<IRoleValidator<AppRole>, RoleValidator>();

    builder.Services.AddIdentityCore<AppUser>(opts => {
        opts.Tokens.EmailConfirmationTokenProvider = "SimpleEmail";
        opts.Tokens.ChangeEmailTokenProvider = "SimpleEmail";
        opts.Tokens.PasswordResetTokenProvider = TokenOptions.DefaultPhoneProvider;
        opts.Password.RequireNonAlphanumeric = false;
        opts.Password.RequireLowercase = false;
        opts.Password.RequireUppercase = false;
        opts.Password.RequireDigit = false;
        opts.Password.RequiredLength = 8;
    })
    .AddTokenProvider<EmailConfirmationTokenGenerator>("SimpleEmail")
    .AddTokenProvider<PhoneConfirmationTokenGenerator>(
        TokenOptions.DefaultPhoneProvider)
    .AddSignInManager()
    .AddRoles<AppRole>();

    builder.Services.AddAuthentication(opts => {
        opts.DefaultScheme = IdentityConstants.ApplicationScheme;
    }).AddCookie(IdentityConstants.ApplicationScheme, opts => {
        opts.LoginPath = "/signin";
        opts.AccessDeniedPath = "/signin/403";
    });
    builder.Services.AddAuthorization(opts => {
        AuthorizationPolicies.AddPolicies(opts);
    });
    builder.Services.AddRazorPages();
    builder.Services.AddControllersWithViews();

    var app = builder.Build();

    app.UseStaticFiles();

    app.UseAuthentication();

    app.UseMiddleware<RoleMemberships>();
    app.UseAuthorization();

    app.UseAuthorization();

    app.MapRazorPages();
    app.MapDefaultControllerRoute();
    app.MapFallbackToPage("/Secret");

    app.Run();

***

Use the following code for `Listing 19-21`:

    using ExampleApp.Identity;
    using Microsoft.AspNetCore.Identity;
    using Microsoft.AspNetCore.Mvc;
    using Microsoft.AspNetCore.Mvc.RazorPages;
    using System.Collections.Generic;
    using System.Linq;
    using System.Security.Claims;
    using System.Threading.Tasks;

    namespace ExampleApp.Pages.Store {

        public class RoleClaimsModel : PageModel {

            public RoleClaimsModel(RoleManager<AppRole> roleManager)
                => RoleManager = roleManager;

            public RoleManager<AppRole> RoleManager { get; set; }

            public AppRole Role { get; set; } = new();

            public IEnumerable<Claim> Claims => Role.Claims ?? new List<Claim>();

            public async Task OnGet(string id) {
                Role = await RoleManager.FindByIdAsync(id);
            }

            public async Task<IActionResult> OnPostAdd(string id, string type,
                    string value) {
                Role = await RoleManager.FindByIdAsync(id);
                await RoleManager.AddClaimAsync(Role, new Claim(type, value));
                return RedirectToPage();
            }

            public async Task<IActionResult> OnPostEdit(string id, string type,
                    string value, string oldType, string oldValue) {
                Role = await RoleManager.FindByIdAsync(id);
                await RoleManager.RemoveClaimAsync(Role, new Claim(oldType, oldValue));
                await RoleManager.AddClaimAsync(Role, new Claim(type, value));
                return RedirectToPage();
            }

            public async Task<IActionResult> OnPostDelete(string id, string type,
                    string value) {
                Role = await RoleManager.FindByIdAsync(id);
                await RoleManager.RemoveClaimAsync(Role, new Claim(type, value));
                return RedirectToPage();
            }
        }
    }

***

Use the following code for `Listing 19-23`:

    @page
    @using System.Security.Claims
    @using ExampleApp.Identity
    @using Microsoft.AspNetCore.Identity
    @inject UserManager<AppUser> UserManager

    @{

    string GetName(string claimType) =>
                (Uri.IsWellFormedUriString(claimType, UriKind.Absolute)
                    ? System.IO.Path.GetFileName(new Uri(claimType).LocalPath)
                    : claimType);
    }

    <h4 class="bg-secondary text-white text-center p-2">
        Live Claims for @(User.Identity?.Name ?? "No User")
    </h4>

    <table class="table table-sm table-striped table-bordered">
        <thead><tr><th>Type</th><th>Value</th></tr></thead>
        <tbody>
            @foreach (Claim claim in User.Claims) {
                <tr><td>@GetName(claim.Type)</td><td>@claim.Value</td></tr>
            }
        </tbody>
    </table>

***
