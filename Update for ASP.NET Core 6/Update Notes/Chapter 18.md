# Changes for Chapter 18

## The changes required in this chapter are for null state analysis and the introduction of the minimal API for configuring ASP.NET Core applications.
***

Use the following commands for `Listing 18-3`:


    using Microsoft.AspNetCore.Authentication;
    using Microsoft.AspNetCore.Mvc;
    using Microsoft.AspNetCore.Mvc.RazorPages;
    using Microsoft.AspNetCore.Mvc.Rendering;
    using System.Security.Claims;
    using Microsoft.AspNetCore.Identity;
    using System.Linq;
    using ExampleApp.Identity;

    namespace ExampleApp.Pages {
        public class SignInModel : PageModel {

            public SignInModel(UserManager<AppUser> userManager,
                    SignInManager<AppUser> signInManager) {
                UserManager = userManager;
                SignInManager = signInManager;
            }

            public UserManager<AppUser> UserManager { get; set; }
            public SignInManager<AppUser> SignInManager { get; set; }

            public SelectList Users => new SelectList(
                UserManager.Users.OrderBy(u => u.EmailAddress),
                    "EmailAddress", "EmailAddress");


            public string Username { get; set; } = String.Empty;

            public int? Code { get; set; }

            public void OnGet(int? code) {
                Code = code;
                Username = User.Identity?.Name ?? "(No Signed In User)";
            }

            public async Task<ActionResult> OnPost(string username,
                    [FromQuery] string returnUrl) {

                //Claim claim = new Claim(ClaimTypes.Name, username);
                //ClaimsIdentity ident = new ClaimsIdentity("simpleform");
                //ident.AddClaim(claim);
                //await HttpContext.SignInAsync(new ClaimsPrincipal(ident));
                AppUser user = await UserManager.FindByEmailAsync(username);
                await SignInManager.SignInAsync(user, false);
                return Redirect(returnUrl ?? "/signin");
            }
        }
    }

***

Ignore `Listing 18-4` and configure the application using the following code in the `Program.cs` file:

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
    builder.Services.AddSingleton<IEmailSender, ConsoleEmailSender>();
    builder.Services.AddSingleton<ISMSSender, ConsoleSMSSender>();
    builder.Services.AddSingleton<IUserClaimsPrincipalFactory<AppUser>,
        AppUserClaimsPrincipalFactory>();


    builder.Services.AddIdentityCore<AppUser>(opts => {
        opts.Tokens.EmailConfirmationTokenProvider = "SimpleEmail";
        opts.Tokens.ChangeEmailTokenProvider = "SimpleEmail";
    })
    .AddTokenProvider<EmailConfirmationTokenGenerator>("SimpleEmail")
    .AddTokenProvider<PhoneConfirmationTokenGenerator>(
        TokenOptions.DefaultPhoneProvider)
    .AddSignInManager();


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

Use the following commands for `Listing 18-5`:

    using System.Security.Claims;

    namespace ExampleApp.Identity {
        public class AppUser {

            public string Id { get; set; } = Guid.NewGuid().ToString();

            public string UserName { get; set; } = String.Empty;

            public string NormalizedUserName { get; set; } = String.Empty;


            public string EmailAddress { get; set; } = String.Empty;
            public string NormalizedEmailAddress { get; set; } = String.Empty;
            public bool EmailAddressConfirmed { get; set; }

            public string PhoneNumber { get; set; } = String.Empty;
            public bool PhoneNumberConfirmed { get; set; }

            public string FavoriteFood { get; set; } = String.Empty;
            public string Hobby { get; set; } = String.Empty;

            public IList<Claim> Claims { get; set; } = new List<Claim>();

            public string SecurityStamp { get; set; } = String.Empty;
            public string? PasswordHash { get; set; }
        }
    }

***

Ignore `Listing 18-7` and configure the application using the following code in the `Program.cs` file:

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
    builder.Services.AddSingleton<IEmailSender, ConsoleEmailSender>();
    builder.Services.AddSingleton<ISMSSender, ConsoleSMSSender>();
    builder.Services.AddSingleton<IUserClaimsPrincipalFactory<AppUser>,
        AppUserClaimsPrincipalFactory>();
    builder.Services.AddSingleton<IPasswordHasher<AppUser>, SimplePasswordHasher>();

    builder.Services.AddIdentityCore<AppUser>(opts => {
        opts.Tokens.EmailConfirmationTokenProvider = "SimpleEmail";
        opts.Tokens.ChangeEmailTokenProvider = "SimpleEmail";
    })
    .AddTokenProvider<EmailConfirmationTokenGenerator>("SimpleEmail")
    .AddTokenProvider<PhoneConfirmationTokenGenerator>(
        TokenOptions.DefaultPhoneProvider)
    .AddSignInManager();


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

Use the following code for `Listing 18-8`:

    using Microsoft.AspNetCore.Identity;

    namespace ExampleApp.Identity.Store {

        public partial class UserStore : IUserPasswordStore<AppUser> {

            public Task<string?> GetPasswordHashAsync(AppUser user,
                CancellationToken token) => Task.FromResult(user.PasswordHash);

            public Task<bool> HasPasswordAsync(AppUser user, CancellationToken token)
                => Task.FromResult(!string.IsNullOrEmpty(user.PasswordHash));

            public Task SetPasswordHashAsync(AppUser user, string passwordHash,
                    CancellationToken token) {
                user.PasswordHash = passwordHash;
                return Task.CompletedTask;
            }
        }
    }


***

Use the following code for `Listing 18-11`:

    using Microsoft.AspNetCore.Authentication;
    using Microsoft.AspNetCore.Mvc;
    using Microsoft.AspNetCore.Mvc.RazorPages;
    using Microsoft.AspNetCore.Mvc.Rendering;
    using System.Security.Claims;
    using Microsoft.AspNetCore.Identity;
    using System.Linq;
    using ExampleApp.Identity;
    using SignInResult = Microsoft.AspNetCore.Identity.SignInResult;

    namespace ExampleApp.Pages {
        public class SignInModel : PageModel {

            public SignInModel(UserManager<AppUser> userManager,
                    SignInManager<AppUser> signInManager) {
                UserManager = userManager;
                SignInManager = signInManager;
            }

            public UserManager<AppUser> UserManager { get; set; }
            public SignInManager<AppUser> SignInManager { get; set; }

            public SelectList Users => new SelectList(
                UserManager.Users.OrderBy(u => u.EmailAddress),
                    "EmailAddress", "EmailAddress");


            public string Username { get; set; } = String.Empty;

            public int? Code { get; set; }

            public void OnGet(int? code) {
                Code = code;
                Username = User.Identity?.Name ?? "(No Signed In User)";
            }

            public async Task<ActionResult> OnPost(string username,
                    string password, [FromQuery] string returnUrl) {
                SignInResult result = SignInResult.Failed;
                AppUser user = await UserManager.FindByEmailAsync(username);
                if (user != null && !string.IsNullOrEmpty(password)) {
                    result = await SignInManager.PasswordSignInAsync(user, password,
                        false, true);
                }
                if (!result.Succeeded) {
                    Code = StatusCodes.Status401Unauthorized;
                    return Page();
                }
                return Redirect(returnUrl ?? "/signin");
            }
        }
    }

***

Use the following code for `Listing 18-12`:

    @page "/password/change/{success:bool?}"
    @model ExampleApp.Pages.Store.PasswordChangeModel

    <h4 class="bg-primary text-white text-center p-2">Change Password</h4>

    <div asp-validation-summary="All" class="text-danger m-2"></div>

    @if (Model.Success) {
        <h5 class="bg-success text-white text-center p-2">Password Changed</h5> 
    }

    <div class="m-2">
        <form method="post">
            <table class="table table-sm table-striped">
                <tbody>
                    <tr><th>Your Username</th>
                        <td>@HttpContext.User.Identity?.Name</td></tr>
                    <tr>
                        <th>Existing Password</th>
                        <td><input class="w-100" type="password" name="oldPassword" />
                        </td>
                    </tr>
                    <tr>
                        <th>New Password</th>
                        <td><input class="w-100" type="password" name="newPassword" />
                        </td>
                    </tr>
                </tbody>
            </table>
            <div class="text-center">
                <button class="btn btn-primary">Change</button>
                <a class="btn btn-secondary" asp-page="/SignIn">Back</a>
            </div>
        </form>
    </div>

***

Use the following code for `Listing 18-13`:

    using System.Threading.Tasks;
    using ExampleApp.Identity;
    using Microsoft.AspNetCore.Identity;
    using Microsoft.AspNetCore.Mvc;
    using Microsoft.AspNetCore.Mvc.RazorPages;

    namespace ExampleApp.Pages.Store {
        public class PasswordChangeModel : PageModel {

            public PasswordChangeModel(UserManager<AppUser> manager) =>
                UserManager = manager;

            public UserManager<AppUser> UserManager { get; set; }

            [BindProperty(SupportsGet = true)]
            public bool Success { get; set; } = false;

            public async Task<IActionResult> OnPost(string oldPassword,
                    string newPassword) {
                string? username = HttpContext.User.Identity?.Name;
                if (username != null) {
                    AppUser user = await UserManager.FindByNameAsync(username);
                    if (user != null && !string.IsNullOrEmpty(oldPassword)
                            && !string.IsNullOrEmpty(newPassword)) {
                        IdentityResult result = await UserManager.ChangePasswordAsync(
                            user, oldPassword, newPassword);
                        if (result.Succeeded) {
                            Success = true;
                        } else {
                            foreach (IdentityError err in result.Errors) {
                                ModelState.AddModelError("", err.Description);
                            }
                        }
                    }
                }
                return Page();
            }
        }
    }

***

Ignore `Listing 18-14` and configure the application using the following code in the `Program.cs` file:

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
    builder.Services.AddSingleton<IEmailSender, ConsoleEmailSender>();
    builder.Services.AddSingleton<ISMSSender, ConsoleSMSSender>();
    builder.Services.AddSingleton<IUserClaimsPrincipalFactory<AppUser>,
        AppUserClaimsPrincipalFactory>();
    builder.Services.AddSingleton<IPasswordHasher<AppUser>, SimplePasswordHasher>();

    builder.Services.AddIdentityCore<AppUser>(opts => {
        opts.Tokens.EmailConfirmationTokenProvider = "SimpleEmail";
        opts.Tokens.ChangeEmailTokenProvider = "SimpleEmail";
        opts.Tokens.PasswordResetTokenProvider = TokenOptions.DefaultPhoneProvider;
    })
    .AddTokenProvider<EmailConfirmationTokenGenerator>("SimpleEmail")
    .AddTokenProvider<PhoneConfirmationTokenGenerator>(
        TokenOptions.DefaultPhoneProvider)
    .AddSignInManager();


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

Use the following code for `Listing 18-18`:

    using System;
    using System.Collections.Generic;
    using System.Linq;
    using System.Threading.Tasks;
    using ExampleApp.Identity;
    using Microsoft.AspNetCore.Identity;
    using Microsoft.AspNetCore.Mvc;
    using Microsoft.AspNetCore.Mvc.RazorPages;

    namespace ExampleApp.Pages.Store {

        public class PasswordResetConfirmModel : PageModel {

            public PasswordResetConfirmModel(UserManager<AppUser> manager)
                => UserManager = manager;

            public UserManager<AppUser> UserManager { get; set; }

            [BindProperty(SupportsGet = true)]
            public string Email { get; set; } = String.Empty;

            [BindProperty(SupportsGet = true)]
            public bool Changed { get; set; } = false;

            public async Task<IActionResult> OnPostAsync(string password, string token) {
                AppUser user = await UserManager.FindByEmailAsync(Email);
                if (user != null) {
                    IdentityResult result = await UserManager.ResetPasswordAsync(user,
                        token, password);
                    if (result.Succeeded) {
                        return RedirectToPage(new { Changed = true });
                    } else {
                        foreach (IdentityError err in result.Errors) {
                            ModelState.AddModelError("", err.Description);
                        }
                    }
                } else {
                    ModelState.AddModelError("", "Password Change Error");
                }
                return Page();
            }
        }
    }

***

Use the following code for `Listing 18-19`:

    @page "{code:int?}"
    @model ExampleApp.Pages.SignInModel
    @using Microsoft.AspNetCore.Http

    @if (Model.Code == StatusCodes.Status401Unauthorized) {
        <h3 class="bg-warning text-white text-center p-2">
            401 - Challenge Response
        </h3>
    } else if (Model.Code == StatusCodes.Status403Forbidden) {
        <h3 class="bg-danger text-white text-center p-2">
            403 - Forbidden Response
        </h3>
    }
    <h4 class="bg-info text-white m-2 p-2">
        Current User: @Model.Username
    </h4>

    <div class="m-2">
        <form method="post">
            <div class="form-group">
                <label>User</label>
                <select class="form-control" 
                        asp-for="Username" asp-items="@Model.Users">
                </select>
            </div>
            <div class="form-group">
                <label>Password</label>
                <input class="form-control" type="password" name="password" />
            </div>
            <button class="btn btn-info" type="submit">Sign In</button>
            @if (User.Identity?.IsAuthenticated == true) {
                <a asp-page="/Store/PasswordChange" class="btn btn-secondary"
                    asp-route-id="@Model.User?
                            .FindFirst(ClaimTypes.NameIdentifier)?.Value">
                        Change Password
                </a>
            } else {
            <a class="btn btn-secondary" href="/password/reset">Reset Password</a>
            }
        </form>
    </div>

***

Ignore `Listing 18-20` and configure the application using the following code in the `Program.cs` file:

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
    builder.Services.AddSingleton<IEmailSender, ConsoleEmailSender>();
    builder.Services.AddSingleton<ISMSSender, ConsoleSMSSender>();
    builder.Services.AddSingleton<IUserClaimsPrincipalFactory<AppUser>,
        AppUserClaimsPrincipalFactory>();
    builder.Services.AddSingleton<IPasswordHasher<AppUser>, SimplePasswordHasher>();

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
    .AddSignInManager();


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

Use the following code for `Listing 18-21`:

    using Microsoft.AspNetCore.Identity;
    using System;
    using System.Linq;
    using System.Net.Http;
    using System.Threading.Tasks;
    using System.Security.Cryptography;
    using System.Text;
    using System.Collections.Generic;

    namespace ExampleApp.Identity {
        public class PasswordValidator : IPasswordValidator<AppUser> {
            // set this field to false to disable the web service check
            private const bool remoteCheck = true;

            public async Task<IdentityResult> ValidateAsync(UserManager<AppUser> manager,
                    AppUser user, string password) {
                IEnumerable<IdentityError> errors = CheckTop20(password);
                if (remoteCheck) {
                    errors = errors.Concat(await CheckHaveIBeenPwned(password));
                }
                return errors.Count() == 0
                    ? IdentityResult.Success : IdentityResult.Failed(errors.ToArray());
            }

            private async Task<IEnumerable<IdentityError>> CheckHaveIBeenPwned(
                    string password) {
                string hash = BitConverter.ToString(SHA1.Create()
                    .ComputeHash(Encoding.UTF8.GetBytes(password)))
                    .Replace("-", string.Empty);
                string firstSection = hash[0..5];
                string secondSection = hash[5..];
                HttpResponseMessage response = await new HttpClient()
                    .GetAsync($"https://api.pwnedpasswords.com/range/{firstSection}");
                string matchingHashes = await response.Content.ReadAsStringAsync();
                string[] matches = matchingHashes.Split("\n",
                    StringSplitOptions.RemoveEmptyEntries);
                string? match = matches.FirstOrDefault(match =>
                    match.StartsWith(secondSection,
                        StringComparison.CurrentCultureIgnoreCase));
                if (match == null) {
                    return Enumerable.Empty<IdentityError>();
                } else {
                    long count = long.Parse(match.Split(":")[1]);
                    return new[] {new IdentityError {
                        Description = $"Password has been compromised {count:N0} times"
                    }};
                }
            }

            private IEnumerable<IdentityError> CheckTop20(string password) {
                if (commonPasswords.Any(commonPassword =>
                    string.Equals(commonPassword, password,
                        StringComparison.CurrentCultureIgnoreCase))) {
                    return new[] {
                        new IdentityError {
                            Description = "The top 20 passwords cannot be used"
                        }
                    };
                }
                return Enumerable.Empty<IdentityError>();
            }

            private static string[] commonPasswords = new[] {
                "123456", "123456789", "qwerty", "password", "1111111", "12345678",
                "abc123", "1234567", "password1", "12345", "1234567890", "123123",
                "000000", "Iloveyou", "1234", "1q2w3e4r5t", "Qwertyuiop", "123",
                "Monkey", "Dragon"};
        }
    }

***

Ignore `Listing 18-22` and configure the application using the following code in the `Program.cs` file:

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
    builder.Services.AddSingleton<IUserClaimsPrincipalFactory<AppUser>,
        AppUserClaimsPrincipalFactory>();
    builder.Services.AddSingleton<IPasswordHasher<AppUser>, SimplePasswordHasher>();

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
    .AddSignInManager();

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

Use the following code for `Listing 18-25`:

    using ExampleApp.Identity;
    using Microsoft.AspNetCore.Identity;
    using Microsoft.AspNetCore.Mvc;
    using Microsoft.AspNetCore.Mvc.RazorPages;
    using System.Threading.Tasks;

    namespace ExampleApp.Pages.Store {

        public class UsersModel : PageModel {

            public UsersModel(UserManager<AppUser> userMgr) => UserManager = userMgr;

            public UserManager<AppUser> UserManager { get; set; }

            public AppUser AppUserObject { get; set; } = new AppUser();

            public async Task OnGetAsync(string? id) {
                if (id != null) {
                    AppUserObject = await UserManager.FindByIdAsync(id) ?? new AppUser();
                }
            }

            public async Task<IActionResult> OnPost(AppUser user, string newPassword) {
                IdentityResult result = IdentityResult.Success;
                AppUser storeUser = await UserManager.FindByIdAsync(user.Id);
                if (storeUser == null) {
                    if (string.IsNullOrEmpty(newPassword)) {
                        ModelState.AddModelError("", "Password Required");
                        return Page();
                    }
                    result = await UserManager.CreateAsync(user, newPassword);
                } else {
                    storeUser.UpdateFrom(user, out bool changed);
                    if (newPassword != null) {
                        if (await UserManager.HasPasswordAsync(storeUser)) {
                            await UserManager.RemovePasswordAsync(storeUser);
                        }
                        result = await UserManager.AddPasswordAsync(storeUser,
                            newPassword);
                    }
                    if (changed && UserManager.SupportsUserSecurityStamp) {
                        await UserManager.UpdateSecurityStampAsync(storeUser);
                    }
                    if (result.Succeeded) {
                        result = await UserManager.UpdateAsync(storeUser);
                    }
                }
                if (result.Succeeded) {
                    return RedirectToPage("users", new { searchname = user.Id });
                } else {
                    foreach (IdentityError err in result.Errors) {
                        ModelState.AddModelError("", err.Description ?? "Error");
                    }
                    AppUserObject = user;
                    return Page();
                }
            }
        }
    }

***
