# Changes for Chapter 20

## The changes required in this chapter are for null state analysis and the introduction of the minimal API for configuring ASP.NET Core applications.
***

Use the following commands for `Listing 20-2`:

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

            public bool CanUserBeLockedout { get; set; } = true;
            public int FailedSignInCount { get; set; }
            public DateTimeOffset? LockoutEnd { get; set; }
        }
    }

***

Ignore `Listing 20-6` and configure the application using the following code in the `Program.cs` file:

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
        opts.Lockout.MaxFailedAccessAttempts = 3;
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

Use the following code for `Listing 20-7`:

    using ExampleApp.Identity;
    using Microsoft.AspNetCore.Identity;
    using Microsoft.AspNetCore.Mvc;
    using Microsoft.AspNetCore.Mvc.RazorPages;
    using Microsoft.AspNetCore.Mvc.Rendering;
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

            public string? Message { get; set; }

            public void OnGet(int? code) {
                if (code == StatusCodes.Status401Unauthorized) {
                    Message = "401 - Challenge Response";
                } else if (code == StatusCodes.Status403Forbidden) {
                    Message = "403 - Forbidden Response";
                }
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
                    if (result.IsLockedOut && user != null) {
                        TimeSpan remaining = (await UserManager
                            .GetLockoutEndDateAsync(user))
                            .GetValueOrDefault().Subtract(DateTimeOffset.Now);
                        Message = $"Locked Out for {remaining.Minutes} mins and"
                            + $" {remaining.Seconds} secs";
                    } else {
                        Message = "Access Denied";
                    }
                    return Page();
                }
                return Redirect(returnUrl ?? "/signin");
            }
        }
    }

***

Use the following code for `Listing 20-8`:

    @page "{code:int?}"
    @model ExampleApp.Pages.SignInModel
    @using Microsoft.AspNetCore.Http

    @if (!string.IsNullOrEmpty(Model.Message)) {
        <h3 class="bg-danger text-white text-center p-2">
            @Model.Message
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

Use the following code for `Listing 20-11`:

    using ExampleApp.Identity;
    using Microsoft.AspNetCore.Identity;
    using Microsoft.AspNetCore.Mvc;
    using Microsoft.AspNetCore.Mvc.RazorPages;
    using Microsoft.AspNetCore.Mvc.Rendering;
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

            public string? Message { get; set; }

            public void OnGet(int? code) {
                if (code == StatusCodes.Status401Unauthorized) {
                    Message = "401 - Challenge Response";
                } else if (code == StatusCodes.Status403Forbidden) {
                    Message = "403 - Forbidden Response";
                }
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
                    if (result.IsLockedOut && user != null) {
                        TimeSpan remaining = (await UserManager
                            .GetLockoutEndDateAsync(user))
                            .GetValueOrDefault().Subtract(DateTimeOffset.Now);
                        Message = $"Locked Out for {remaining.Minutes} mins and"
                            + $" {remaining.Seconds} secs";
                    } else if (result.IsNotAllowed) {
                        Message = "Sign In Not Allowed";
                    } else {
                        Message = "Access Denied";
                    }
                    return Page();
                }
                return Redirect(returnUrl ?? "/signin");
            }
        }
    }

***

Ignore `Listing 20-12` and configure the application using the following code in the `Program.cs` file:

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
    builder.Services.AddSingleton<IUserConfirmation<AppUser>, UserConfirmation>();

    builder.Services.AddIdentityCore<AppUser>(opts => {
        opts.Tokens.EmailConfirmationTokenProvider = "SimpleEmail";
        opts.Tokens.ChangeEmailTokenProvider = "SimpleEmail";
        opts.Tokens.PasswordResetTokenProvider = TokenOptions.DefaultPhoneProvider;
        opts.Password.RequireNonAlphanumeric = false;
        opts.Password.RequireLowercase = false;
        opts.Password.RequireUppercase = false;
        opts.Password.RequireDigit = false;
        opts.Password.RequiredLength = 8;
        opts.Lockout.MaxFailedAccessAttempts = 3;
        opts.SignIn.RequireConfirmedAccount = true;
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

Use the following code for `Listing 20-13`:

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

        public bool CanUserBeLockedout { get; set; } = true;
        public int FailedSignInCount { get; set; }
        public DateTimeOffset? LockoutEnd { get; set; }

        public bool TwoFactorEnabled { get; set; }
    }
}

***

Ignore `Listing 20-19` and configure the application using the following code in the `Program.cs` file:

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
    builder.Services.AddSingleton<IUserConfirmation<AppUser>, UserConfirmation>();

    builder.Services.AddIdentityCore<AppUser>(opts => {
        opts.Tokens.EmailConfirmationTokenProvider = "SimpleEmail";
        opts.Tokens.ChangeEmailTokenProvider = "SimpleEmail";
        opts.Tokens.PasswordResetTokenProvider = TokenOptions.DefaultPhoneProvider;
        opts.Password.RequireNonAlphanumeric = false;
        opts.Password.RequireLowercase = false;
        opts.Password.RequireUppercase = false;
        opts.Password.RequireDigit = false;
        opts.Password.RequiredLength = 8;
        opts.Lockout.MaxFailedAccessAttempts = 3;
        opts.SignIn.RequireConfirmedAccount = true;
    })
    .AddTokenProvider<EmailConfirmationTokenGenerator>("SimpleEmail")
    .AddTokenProvider<PhoneConfirmationTokenGenerator>(
        TokenOptions.DefaultPhoneProvider)
    .AddTokenProvider<TwoFactorSignInTokenGenerator>
        (IdentityConstants.TwoFactorUserIdScheme)
    .AddSignInManager()
    .AddRoles<AppRole>();

    builder.Services.AddAuthentication(opts => {
        opts.DefaultScheme = IdentityConstants.ApplicationScheme;
    }).AddCookie(IdentityConstants.ApplicationScheme, opts => {
        opts.LoginPath = "/signin";
        opts.AccessDeniedPath = "/signin/403";
    })
    .AddCookie(IdentityConstants.TwoFactorUserIdScheme)
    .AddCookie(IdentityConstants.TwoFactorRememberMeScheme);

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

Use the following code for `Listing 20-20`:

    using ExampleApp.Identity;
    using Microsoft.AspNetCore.Identity;
    using Microsoft.AspNetCore.Mvc;
    using Microsoft.AspNetCore.Mvc.RazorPages;
    using Microsoft.AspNetCore.Mvc.Rendering;
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

            public string? Message { get; set; }

            public void OnGet(int? code) {
                if (code == StatusCodes.Status401Unauthorized) {
                    Message = "401 - Challenge Response";
                } else if (code == StatusCodes.Status403Forbidden) {
                    Message = "403 - Forbidden Response";
                }
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
                    if (result.IsLockedOut && user != null) {
                        TimeSpan remaining = (await UserManager
                            .GetLockoutEndDateAsync(user))
                            .GetValueOrDefault().Subtract(DateTimeOffset.Now);
                        Message = $"Locked Out for {remaining.Minutes} mins and"
                            + $" {remaining.Seconds} secs";
                    } else if (result.RequiresTwoFactor) {
                        return RedirectToPage("/SignInTwoFactor", new { returnUrl = returnUrl });
                    } else if (result.IsNotAllowed) {
                        Message = "Sign In Not Allowed";
                    } else {
                        Message = "Access Denied";
                    }
                    return Page();
                }
                return Redirect(returnUrl ?? "/signin");
            }
        }
    }

***

Use the following code for `Listing 20-24`:

    using Microsoft.AspNetCore.Authentication;
    using Microsoft.AspNetCore.Mvc;
    using Microsoft.AspNetCore.Mvc.RazorPages;
    using Microsoft.AspNetCore.Identity;
    using ExampleApp.Identity;

    namespace ExampleApp.Pages {
        public class SignOutModel : PageModel {
            public string Username { get; set; } = String.Empty;

            public SignOutModel(SignInManager<AppUser> manager)
                => SignInManager = manager;

            public SignInManager<AppUser> SignInManager { get; set; }

            public void OnGet() {
                Username = User.Identity?.Name ?? "(No Signed In User)";
            }

            public async Task<ActionResult> OnPost(string forgetMe) {
                if (!string.IsNullOrEmpty(forgetMe)) {
                    await SignInManager.ForgetTwoFactorClientAsync();
                }
                await HttpContext.SignOutAsync();
                return RedirectToPage("SignIn");
            }
        }
    }

***

Ignore `Listing 20-25` and configure the application using the following code in the `Program.cs` file:

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
    builder.Services.AddSingleton<IUserConfirmation<AppUser>, UserConfirmation>();

    builder.Services.AddIdentityCore<AppUser>(opts => {
        opts.Tokens.EmailConfirmationTokenProvider = "SimpleEmail";
        opts.Tokens.ChangeEmailTokenProvider = "SimpleEmail";
        opts.Tokens.PasswordResetTokenProvider = TokenOptions.DefaultPhoneProvider;
        opts.Password.RequireNonAlphanumeric = false;
        opts.Password.RequireLowercase = false;
        opts.Password.RequireUppercase = false;
        opts.Password.RequireDigit = false;
        opts.Password.RequiredLength = 8;
        opts.Lockout.MaxFailedAccessAttempts = 3;
        opts.SignIn.RequireConfirmedAccount = true;
    })
    .AddTokenProvider<EmailConfirmationTokenGenerator>("SimpleEmail")
    .AddTokenProvider<PhoneConfirmationTokenGenerator>(
        TokenOptions.DefaultPhoneProvider)
    .AddTokenProvider<TwoFactorSignInTokenGenerator>
        (IdentityConstants.TwoFactorUserIdScheme)
    .AddSignInManager()
    .AddRoles<AppRole>();

    builder.Services.AddAuthentication(opts => {
        opts.DefaultScheme = IdentityConstants.ApplicationScheme;
    }).AddCookie(IdentityConstants.ApplicationScheme, opts => {
        opts.LoginPath = "/signin";
        opts.AccessDeniedPath = "/signin/403";
    })
    .AddCookie(IdentityConstants.TwoFactorUserIdScheme)
    .AddCookie(IdentityConstants.TwoFactorRememberMeScheme);

    builder.Services.AddAuthorization(opts => {
        AuthorizationPolicies.AddPolicies(opts);
        opts.AddPolicy("Full2FARequired", builder => {
            builder.RequireClaim("amr", "mfa");
        });
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

Use the following code for `Listing 20-28`:

    using Microsoft.AspNetCore.Authorization;
    using Microsoft.AspNetCore.Mvc;
    using Microsoft.AspNetCore.Mvc.Filters;

    namespace ExampleApp.Identity {

        public class Full2FARequiredFilterAttribute : Attribute,
                IAsyncPageFilter, IAsyncActionFilter {

            public async Task OnActionExecutionAsync(ActionExecutingContext context,
                    ActionExecutionDelegate next) {
                IActionResult? result = await ApplyPolicy(context.HttpContext);
                if (result != null) {
                    context.Result = result;
                } else {
                    await next.Invoke();
                }
            }

            public async Task OnPageHandlerExecutionAsync(PageHandlerExecutingContext
                    context, PageHandlerExecutionDelegate next) {
                IActionResult? result = await ApplyPolicy(context.HttpContext);
                if (result != null) {
                    context.Result = result;
                } else {
                    await next.Invoke();
                }
            }

            public async Task<IActionResult?> ApplyPolicy(HttpContext context) {
                IAuthorizationService authService =
                    context.RequestServices.GetRequiredService<IAuthorizationService>();
                if (!(await authService.AuthorizeAsync(context.User,
                    "Full2FARequired")).Succeeded) {
                    return new RedirectToPageResult("/Full2FARequired",
                        new { returnUrl = Path(context) });
                }
                return null;
            }

            public Task OnPageHandlerSelectionAsync(PageHandlerSelectedContext context) {
                return Task.CompletedTask;
            }

            private string Path(HttpContext context) =>
                $"{context.Request.Path}{context.Request.QueryString}";
        }
    }

***