# Changes for Chapter 22

## Not all of the Identity API methods have  been correctly annotated for null state analysis, which requires the use of the #pragma directive in some listings. 
***

Use the following code for `Listing 22-2`:

    using Microsoft.AspNetCore.Authentication;

    namespace ExampleApp.Custom {
        public class ExternalAuthHandler : IAuthenticationHandler {

            public AuthenticationScheme? Scheme { get; set; }
            public HttpContext? Context { get; set; }

            public Task InitializeAsync(AuthenticationScheme scheme,
                    HttpContext context) {
                Scheme = scheme;
                Context = context;
                return Task.CompletedTask;
            }

            public Task<AuthenticateResult> AuthenticateAsync() {
                return Task.FromResult(AuthenticateResult.NoResult());
            }

            public Task ChallengeAsync(AuthenticationProperties? properties) {
                return Task.CompletedTask;
            }

            public Task ForbidAsync(AuthenticationProperties? properties) {
                return Task.CompletedTask;
            }
        }
    }

***

Ignore `Listing 22-3` and configure the application using the following code in the `Program.cs` file:

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
    //builder.Services.AddSingleton<IUserConfirmation<AppUser>, UserConfirmation>();

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
    .AddTokenProvider<AuthenticatorTokenProvider<AppUser>>
        (TokenOptions.DefaultAuthenticatorProvider)
    .AddSignInManager()
    .AddRoles<AppRole>();

    builder.Services.AddAuthentication(opts => {
        opts.DefaultScheme = IdentityConstants.ApplicationScheme;
        opts.AddScheme<ExternalAuthHandler>("demoAuth", "Demo Service");
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

Use the following code for `Listing 22-4`:

    @page "{code:int?}"
    @model ExampleApp.Pages.SignInModel
    @using Microsoft.AspNetCore.Http

    @if (!string.IsNullOrEmpty(Model.Message)) {
        <h3 class="bg-danger text-white text-center p-2">@Model.Message</h3>
    } 

    <h4 class="bg-info text-white m-2 p-2">Current User: @Model.Username</h4>

    <div class="container-fluid">
        <div class="row">
            <div class="col-6 border p-2 h-100">
                <h4 class="text-center">Local Authentication</h4>
                <form method="post">
                    <div class="form-group">
                        <label>User</label>
                        <select class="form-control" 
                                asp-for="Username" asp-items="@Model.Users">
                        </select>
                    </div>
                    <div class="form-group">
                        <label>Password</label>
                        <input class="form-control" type="password" 
                            name="password" value="MySecret1$" />
                    </div>
                    <button class="btn btn-info" type="submit">Sign In</button>
                    @if (User.Identity?.IsAuthenticated == true) {
                        <a asp-page="/Store/PasswordChange" class="btn btn-secondary"
                            asp-route-id="@Model.User?
                                    .FindFirst(ClaimTypes.NameIdentifier)?.Value">
                                Change Password
                        </a>
                    } else {
                        <a class="btn btn-secondary" href="/password/reset">
                            Reset Password
                        </a>
                    }
                </form>
            </div>
            <div class="col-6 text-center">
                <div class="border p-2 h-100">
                    <form method="post">
                        <h4>External Authentication</h4>
                        <div class="mt-4 w-75">
                            @foreach (var scheme in 
                                    await Model.SignInManager
                                        .GetExternalAuthenticationSchemesAsync()) {
                                <div class="mt-2 text-center">
                                    <button class="btn btn-block btn-secondary
                                                m-1 mx-5" type="submit"
                                            asp-page="/externalsignin"
                                            asp-route-returnUrl=
                                                "@Request.Query["returnUrl"]"
                                            asp-route-providername="@scheme.Name">
                                        @scheme.DisplayName
                                    </button>    
                                </div>
                            }
                        </div>
                    </form>
                </div>
            </div>
        </div>
    </div>

***

Use the following code for `Listing 22-6`:

    using ExampleApp.Identity;
    using Microsoft.AspNetCore.Authentication;
    using Microsoft.AspNetCore.Identity;
    using Microsoft.AspNetCore.Mvc;
    using Microsoft.AspNetCore.Mvc.RazorPages;

    namespace ExampleApp.Pages {

        public class ExternalSignInModel : PageModel {

            public ExternalSignInModel(SignInManager<AppUser> signInManager) {
                SignInManager = signInManager;
            }

            public SignInManager<AppUser> SignInManager { get; set; }

            public IActionResult OnPost(string providerName,
                    string returnUrl = "/") {

                string? redirectUrl = Url.Page("./ExternalSignIn",
                    pageHandler: "Correlate", values: new { returnUrl });
                AuthenticationProperties properties = SignInManager
                .ConfigureExternalAuthenticationProperties(providerName,
                    redirectUrl);
                return new ChallengeResult(providerName, properties);
            }
        }
    }

***

Use the following code for `Listing 22-7`:

    using Microsoft.AspNetCore.Authentication;
    using Microsoft.AspNetCore.Identity;
    using System.Security.Claims;

    namespace ExampleApp.Custom {
        public class ExternalAuthHandler : IAuthenticationHandler {

            public AuthenticationScheme? Scheme { get; set; }
            public HttpContext? Context { get; set; }

            public Task InitializeAsync(AuthenticationScheme scheme,
                    HttpContext context) {
                Scheme = scheme;
                Context = context;
                return Task.CompletedTask;
            }

            public Task<AuthenticateResult> AuthenticateAsync() {
                return Task.FromResult(AuthenticateResult.NoResult());
            }

            public async Task ChallengeAsync(AuthenticationProperties? properties) {
                ClaimsIdentity identity = new ClaimsIdentity(Scheme?.Name);
                identity.AddClaims(new[] {
                    new Claim(ClaimTypes.NameIdentifier, "SomeUniqueID"),
                    new Claim(ClaimTypes.Email, "alice@example.com"),
                    new Claim(ClaimTypes.Name, "Alice")
                });
                ClaimsPrincipal principal = new ClaimsPrincipal(identity);
                if (Context != null) {
                    await Context.SignInAsync(IdentityConstants.ExternalScheme,
                        principal, properties);
                }
                Context?.Response.Redirect(properties?.RedirectUri ?? "/");
            }

            public Task ForbidAsync(AuthenticationProperties? properties) {
                return Task.CompletedTask;
            }
        }
    }

***

Ignore `Listing 22-8` and configure the application using the following code in the `Program.cs` file:

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
    //builder.Services.AddSingleton<IUserConfirmation<AppUser>, UserConfirmation>();

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
    .AddTokenProvider<AuthenticatorTokenProvider<AppUser>>
        (TokenOptions.DefaultAuthenticatorProvider)
    .AddSignInManager()
    .AddRoles<AppRole>();

    builder.Services.AddAuthentication(opts => {
        opts.DefaultScheme = IdentityConstants.ApplicationScheme;
        opts.AddScheme<ExternalAuthHandler>("demoAuth", "Demo Service");
    }).AddCookie(IdentityConstants.ApplicationScheme, opts => {
        opts.LoginPath = "/signin";
        opts.AccessDeniedPath = "/signin/403";
    })
    .AddCookie(IdentityConstants.TwoFactorUserIdScheme)
    .AddCookie(IdentityConstants.TwoFactorRememberMeScheme)
    .AddCookie(IdentityConstants.ExternalScheme);

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

Use the following code for `Listing 22-9`:

    using System.Security.Claims;
    using Microsoft.AspNetCore.Identity;

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
            public bool AuthenticatorEnabled { get; set; }
            public string? AuthenticatorKey { get; set; }

            public IList<UserLoginInfo> UserLogins { get; set; } = new List<UserLoginInfo>();
        }
    }

***

Use the following code for `Listing 22-10`:

    using Microsoft.AspNetCore.Identity;

    #pragma warning disable CS8619

    namespace ExampleApp.Identity.Store {

        public partial class UserStore : IUserLoginStore<AppUser> {

            public Task<IList<UserLoginInfo>> GetLoginsAsync(AppUser user,
                    CancellationToken token)
                => Task.FromResult(user.UserLogins ?? new List<UserLoginInfo>());

            public Task AddLoginAsync(AppUser user, UserLoginInfo login,
                    CancellationToken token) {
                if (user.UserLogins == null) {
                    user.UserLogins = new List<UserLoginInfo>();
                }
                user.UserLogins.Add(login);
                return Task.CompletedTask;
            }

            public async Task RemoveLoginAsync(AppUser user, string loginProvider,
                    string providerKey, CancellationToken token)
                => user.UserLogins = (await GetLoginsAsync(user, token)).Where(login
                    => !login.LoginProvider.Equals(loginProvider)
                        && !login.ProviderKey.Equals(providerKey)).ToList();

            public Task<AppUser> FindByLoginAsync(string loginProvider,
                    string providerKey, CancellationToken token) =>
                Task.FromResult(Users.FirstOrDefault(u => u.UserLogins != null &&
                    u.UserLogins.Any(login => login.LoginProvider.Equals(loginProvider)
                        && login.ProviderKey.Equals(providerKey))));
        }
    }

***

Use the following code for `Listing 22-11`:

    using ExampleApp.Identity;
    using Microsoft.AspNetCore.Authentication;
    using Microsoft.AspNetCore.Identity;
    using Microsoft.AspNetCore.Mvc;
    using Microsoft.AspNetCore.Mvc.RazorPages;
    using System.Security.Claims;
    using SignInResult = Microsoft.AspNetCore.Identity.SignInResult;

    namespace ExampleApp.Pages {

        public class ExternalSignInModel : PageModel {

            public ExternalSignInModel(SignInManager<AppUser> signInManager,
                    UserManager<AppUser> userManager) {
                SignInManager = signInManager;
                UserManager = userManager;
            }

            public SignInManager<AppUser> SignInManager { get; set; }
            public UserManager<AppUser> UserManager { get; set; }

            public string? ProviderDisplayName { get; set; }

            public IActionResult OnPost(string providerName,
                    string returnUrl = "/") {

                string? redirectUrl = Url.Page("./ExternalSignIn",
                    pageHandler: "Correlate", values: new { returnUrl });
                AuthenticationProperties properties = SignInManager
                .ConfigureExternalAuthenticationProperties(providerName,
                    redirectUrl);
                return new ChallengeResult(providerName, properties);
            }

            public async Task<IActionResult> OnGetCorrelate(string returnUrl) {
                ExternalLoginInfo info = await SignInManager.GetExternalLoginInfoAsync();
                AppUser user = await UserManager.FindByLoginAsync(info.LoginProvider,
                    info.ProviderKey);
                if (user == null) {
                    string externalEmail =
                        info.Principal.FindFirst(ClaimTypes.Email)?.Value
                            ?? string.Empty;
                    user = await UserManager.FindByEmailAsync(externalEmail);
                    if (user == null) {
                        return RedirectToPage("/ExternalAccountConfirm",
                            new { returnUrl });
                    } else {
                        await UserManager.AddLoginAsync(user, info);
                    }
                }
                SignInResult result = await SignInManager.ExternalLoginSignInAsync(
                    info.LoginProvider, info.ProviderKey, false, false);
                if (result.Succeeded) {
                    return RedirectToPage("ExternalSignIn", "Confirm",
                        new { info.ProviderDisplayName, returnUrl });
                } else if (result.RequiresTwoFactor) {
                    string? postSignInUrl = this.Url.Page("/ExternalSignIn", "Confirm",
                        new { info.ProviderDisplayName, returnUrl });
                    return RedirectToPage("/SignInTwoFactor",
                        new { returnUrl = postSignInUrl });
                }
                return RedirectToPage(new { error = true, returnUrl });
            }

            public async Task OnGetConfirmAsync() {
                string provider = User.FindFirstValue(ClaimTypes.AuthenticationMethod);
                ProviderDisplayName =
                    (await SignInManager.GetExternalAuthenticationSchemesAsync())
                    .FirstOrDefault(s => s.Name == provider)?.DisplayName ?? provider;
            }
        }
    }

***

Use the following code for `Listing 22-12`:

    @page
    @model ExampleApp.Pages.ExternalSignInModel

    <h4 class="bg-info text-white text-center p-2">External Authentication</h4>

    @{ 
        string returnUrl = Request.Query["returnUrl"].Count == 0 ? 
            "/" : Request.Query["returnUrl"];
    }

    @if (Request.Query["error"].Count() > 0) {
        <h5 class="bg-danger text-white text-center m-2 p-2">
            Something went wrong. You could not be signed into the application.
        </h5>
        <h5 class="text-center m-2 p-2">@Request.Query["error"]</h5>
        <div class="text-center">
            <a class="btn btn-info text-center" href="@returnUrl">OK</a>
        </div>
    } else {
        <h5 class="text-center">
            @User.Identity?.Name has been authenticated by @Model.ProviderDisplayName
        </h5>

        <div class="text-center">
            <a class="btn btn-info text-center" href="@returnUrl">Continue</a>
        </div>
    }

***

Use the following code for `Listing 22-13`:

    using Microsoft.AspNetCore.Mvc;

    namespace ExampleApp.Controllers {

        class UserRecord {
            public string? Id { get; set; }
            public string? Name { get; set; }
            public string? EmailAddress { get; set; }
            public string? Password { get; set; }
            public string? Code { get; set; }
            public string? Token { get; set; }
        }

        public class DemoExternalAuthController : Controller {
            private static string expectedID = "MyClientID";
            private static string expectedSecret = "MyClientSecret";
            private static List<UserRecord> users = new List<UserRecord> {
                new UserRecord() {
                    Id = "1", Name = "Alice", EmailAddress = "alice@example.com",
                    Password = "myexternalpassword"
                },
                new UserRecord {
                    Id = "2", Name = "Dora", EmailAddress = "dora@example.com",
                    Password = "myexternalpassword"
                }
            };
        }
    }

***

Use the following code for `Listing 22-14`:

    using Microsoft.AspNetCore.Authentication;
    using Microsoft.AspNetCore.Http;
    using System.Threading.Tasks;
    using System.Security.Claims;
    using Microsoft.AspNetCore.Identity;
    using Microsoft.Extensions.Options;

    namespace ExampleApp.Custom {

        public class ExternalAuthOptions {
            public string ClientId { get; set; } = "MyClientID";
            public string ClientSecret { get; set; } = "MyClientSecret";
        }

        public class ExternalAuthHandler : IAuthenticationHandler {

            public ExternalAuthHandler(IOptions<ExternalAuthOptions> options) {
                Options = options.Value;
            }

            public AuthenticationScheme? Scheme { get; set; }
            public HttpContext? Context { get; set; }

            public ExternalAuthOptions? Options { get; set; }

            public Task InitializeAsync(AuthenticationScheme scheme,
                    HttpContext context) {
                Scheme = scheme;
                Context = context;
                return Task.CompletedTask;
            }

            public Task<AuthenticateResult> AuthenticateAsync() {
                return Task.FromResult(AuthenticateResult.NoResult());
            }

            public async Task ChallengeAsync(AuthenticationProperties? properties) {

                // TODO - authentication implementation 
            }

            public Task ForbidAsync(AuthenticationProperties? properties) {
                return Task.CompletedTask;
            }
        }
    }

***

Ignore `Listing 22-15` and configure the application using the following code in the `Program.cs` file:

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
    //builder.Services.AddSingleton<IUserConfirmation<AppUser>, UserConfirmation>();
    builder.Services.AddOptions<ExternalAuthOptions>();

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
    .AddTokenProvider<AuthenticatorTokenProvider<AppUser>>
        (TokenOptions.DefaultAuthenticatorProvider)
    .AddSignInManager()
    .AddRoles<AppRole>();

    builder.Services.AddAuthentication(opts => {
        opts.DefaultScheme = IdentityConstants.ApplicationScheme;
        opts.AddScheme<ExternalAuthHandler>("demoAuth", "Demo Service");
    }).AddCookie(IdentityConstants.ApplicationScheme, opts => {
        opts.LoginPath = "/signin";
        opts.AccessDeniedPath = "/signin/403";
    })
    .AddCookie(IdentityConstants.TwoFactorUserIdScheme)
    .AddCookie(IdentityConstants.TwoFactorRememberMeScheme)
    .AddCookie(IdentityConstants.ExternalScheme);

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

Use the following code for `Listing 22-16`:

    using Microsoft.AspNetCore.Mvc;

    namespace ExampleApp.Controllers {

        class UserRecord {
            public string? Id { get; set; }
            public string? Name { get; set; }
            public string? EmailAddress { get; set; }
            public string? Password { get; set; }
            public string? Code { get; set; }
            public string? Token { get; set; }
        }

        public class ExternalAuthInfo {
            public string? client_id { get; set; }
            public string? client_secret { get; set; }
            public string? redirect_uri { get; set; }
            public string? scope { get; set; }
            public string? state { get; set; }
            public string? response_type { get; set; }
            public string? grant_type { get; set; }
            public string? code { get; set; }
        }


        public class DemoExternalAuthController : Controller {
            private static string expectedID = "MyClientID";
            private static string expectedSecret = "MyClientSecret";
            private static List<UserRecord> users = new List<UserRecord> {
                new UserRecord() {
                    Id = "1", Name = "Alice", EmailAddress = "alice@example.com",
                    Password = "myexternalpassword"
                },
                new UserRecord {
                    Id = "2", Name = "Dora", EmailAddress = "dora@example.com",
                    Password = "myexternalpassword"
                }
            };

            public IActionResult Authenticate([FromQuery] ExternalAuthInfo info)
            => expectedID == info.client_id ? View((info, string.Empty))
                    : View((info, "Unknown Client"));
        }
    }

***

Use the following code for `Listing 22-17`:

    @model (ExampleApp.Controllers.ExternalAuthInfo info, string error)

    @{ 
        IEnumerable<(string, string?)> KeyValuePairs =
            typeof(ExampleApp.Controllers.ExternalAuthInfo).GetProperties()
                .Select(pi => (pi.Name, pi.GetValue(Model.info)?.ToString()));
    }

    <div class="bg-dark text-white p-2">
        <h4 class="text-center">Demo External Authentication Service</h4>
        <div class="bg-light text-dark m-4 p-5 border">

            @if (!string.IsNullOrEmpty(Model.error)) {
                <div class="h3 bg-danger text-white text-center m-2 p-2">
                    <div>Something Went Wrong</div> 
                    <div class="h5">(@Model.error)</div>
                </div>
            } else {
                <div asp-validation-summary="All" class="text-danger m-2"></div>
                <form method="post" asp-action="Authenticate">
                    @foreach (var tuple in KeyValuePairs) {
                        if (!string.IsNullOrEmpty(tuple.Item2)) {
                            <input type="hidden" name="@tuple.Item1" 
                                value="@tuple.Item2" />
                        }
                    }
                    <div class="p-2">
                        <div class="form-group">
                            <label>Email</label>
                            <input name="email" class="form-control" />
                        </div>
                        <div class="form-group">
                            <label>Password</label>
                            <input name="password" type="password" 
                                class="form-control" />
                        </div>
                        <button type="submit" class="btn btn-sm btn-dark">
                            Authenticate & Return
                        </button>
                    </div>
                </form>  
            }
        </div>
    </div>

***

Use the following code for `Listing 22-18`:

    using Microsoft.AspNetCore.Authentication;
    using Microsoft.AspNetCore.Http;
    using System.Threading.Tasks;
    using System.Security.Claims;
    using Microsoft.AspNetCore.Identity;
    using Microsoft.Extensions.Options;
    using System.Collections.Generic;
    using Microsoft.AspNetCore.DataProtection;

    namespace ExampleApp.Custom {

        public class ExternalAuthOptions {
            public string ClientId { get; set; } = "MyClientID";
            public string ClientSecret { get; set; } = "MyClientSecret";

            public virtual string RedirectRoot { get; set; } = "http://localhost:5000";
            public virtual string RedirectPath { get; set; } = "/signin-external";
            public virtual string Scope { get; set; } = "openid email profile";
            public virtual string StateHashSecret { get; set; } = "mysecret";

            public virtual string AuthenticationUrl { get; set; }
                = "http://localhost:5000/DemoExternalAuth/authenticate";
        }

        public class ExternalAuthHandler : IAuthenticationHandler {

            public ExternalAuthHandler(IOptions<ExternalAuthOptions> options,
                    IDataProtectionProvider dp) {
                Options = options.Value;
                DataProtectionProvider = dp;
            }

            public AuthenticationScheme? Scheme { get; set; }
            public HttpContext? Context { get; set; }
            public ExternalAuthOptions Options { get; set; }
            public IDataProtectionProvider DataProtectionProvider { get; set; }
            public PropertiesDataFormat? PropertiesFormatter { get; set; }


            public Task InitializeAsync(AuthenticationScheme scheme,
                    HttpContext context) {
                Scheme = scheme;
                Context = context;
                PropertiesFormatter = new PropertiesDataFormat(DataProtectionProvider.CreateProtector(typeof(ExternalAuthOptions).FullName ?? "Unknown"));
                return Task.CompletedTask;
            }

            public Task<AuthenticateResult> AuthenticateAsync() {
                return Task.FromResult(AuthenticateResult.NoResult());
            }

            public async Task ChallengeAsync(AuthenticationProperties? properties) {
                Context?.Response.Redirect(await GetAuthenticationUrl(properties));
            }

            protected virtual Task<string>
                    GetAuthenticationUrl(AuthenticationProperties? properties) {
                Dictionary<string, string?> qs = new();
                qs.Add("client_id", Options.ClientId);
                qs.Add("redirect_uri", Options.RedirectRoot + Options.RedirectPath);
                qs.Add("scope", Options.Scope);
                qs.Add("response_type", "code");
                qs.Add("state", PropertiesFormatter!.Protect(properties!));
                return Task.FromResult(Options.AuthenticationUrl + QueryString.Create(qs));
            }

            public Task ForbidAsync(AuthenticationProperties? properties) {
                return Task.CompletedTask;
            }
        }
    }

***

Use the following code for `Listing 22-19`:

    using Microsoft.AspNetCore.Mvc;

    namespace ExampleApp.Controllers {

        class UserRecord {
            public string? Id { get; set; }
            public string? Name { get; set; }
            public string? EmailAddress { get; set; }
            public string? Password { get; set; }
            public string? Code { get; set; }
            public string? Token { get; set; }
        }

        public class ExternalAuthInfo {
            public string? client_id { get; set; }
            public string? client_secret { get; set; }
            public string? redirect_uri { get; set; }
            public string? scope { get; set; }
            public string? state { get; set; }
            public string? response_type { get; set; }
            public string? grant_type { get; set; }
            public string? code { get; set; }
        }


        public class DemoExternalAuthController : Controller {
            private static string expectedID = "MyClientID";
            private static string expectedSecret = "MyClientSecret";
            private static List<UserRecord> users = new List<UserRecord> {
                new UserRecord() {
                    Id = "1", Name = "Alice", EmailAddress = "alice@example.com",
                    Password = "myexternalpassword"
                },
                new UserRecord {
                    Id = "2", Name = "Dora", EmailAddress = "dora@example.com",
                    Password = "myexternalpassword"
                }
            };

            public IActionResult Authenticate([FromQuery] ExternalAuthInfo info)
            => expectedID == info.client_id ? View((info, string.Empty))
                    : View((info, "Unknown Client"));

            [HttpPost]
            public IActionResult Authenticate(ExternalAuthInfo info, string? email,
                    string? password) {
                if (string.IsNullOrEmpty(email) || string.IsNullOrEmpty(password)) {
                    ModelState.AddModelError("", "Email and password required");
                } else {
                    UserRecord? user = users.FirstOrDefault(u =>
                        u.EmailAddress?.Equals(email) == true 
                            && u.Password?.Equals(password) == true);
                    if (user != null) {
                        // user has been successfully authenticated
                    } else {
                        ModelState.AddModelError("", "Email or password incorrect");
                    }
                }
                return View((info, ""));
            }
        }
    }

***

Use the following code for `Listing 22-20`:

    using Microsoft.AspNetCore.Mvc;

    namespace ExampleApp.Controllers {

        class UserRecord {
            public string? Id { get; set; }
            public string? Name { get; set; }
            public string? EmailAddress { get; set; }
            public string? Password { get; set; }
            public string? Code { get; set; }
            public string? Token { get; set; }
        }

        public class ExternalAuthInfo {
            public string? client_id { get; set; }
            public string? client_secret { get; set; }
            public string? redirect_uri { get; set; }
            public string? scope { get; set; }
            public string? state { get; set; }
            public string? response_type { get; set; }
            public string? grant_type { get; set; }
            public string? code { get; set; }
        }


        public class DemoExternalAuthController : Controller {
            private static string expectedID = "MyClientID";
            private static string expectedSecret = "MyClientSecret";
            private static List<UserRecord> users = new List<UserRecord> {
                new UserRecord() {
                    Id = "1", Name = "Alice", EmailAddress = "alice@example.com",
                    Password = "myexternalpassword", Code = "12345"
                },
                new UserRecord {
                    Id = "2", Name = "Dora", EmailAddress = "dora@example.com",
                    Password = "myexternalpassword", Code = "56789"
                }
            };

            public IActionResult Authenticate([FromQuery] ExternalAuthInfo info)
            => expectedID == info.client_id ? View((info, string.Empty))
                    : View((info, "Unknown Client"));

            [HttpPost]
            public IActionResult Authenticate(ExternalAuthInfo info, string? email,
                    string? password) {
                if (string.IsNullOrEmpty(email) || string.IsNullOrEmpty(password)) {
                    ModelState.AddModelError("", "Email and password required");
                } else {
                    UserRecord? user = users.FirstOrDefault(u =>
                        u.EmailAddress?.Equals(email) == true 
                            && u.Password?.Equals(password) == true);
                    if (user != null) {
                        return Redirect(info.redirect_uri
                            + $"?code={user.Code}&scope={info.scope}"
                            + $"&state={info.state}");
                    } else {
                        ModelState.AddModelError("", "Email or password incorrect");
                    }
                }
                return View((info, ""));
            }
        }
    }

***

Use the following code for `Listing 22-21`:

    using Microsoft.AspNetCore.Authentication;
    using Microsoft.AspNetCore.Http;
    using System.Threading.Tasks;
    using System.Security.Claims;
    using Microsoft.AspNetCore.Identity;
    using Microsoft.Extensions.Options;
    using System.Collections.Generic;
    using Microsoft.AspNetCore.DataProtection;

    namespace ExampleApp.Custom {

        public class ExternalAuthOptions {
            public string ClientId { get; set; } = "MyClientID";
            public string ClientSecret { get; set; } = "MyClientSecret";

            public virtual string RedirectRoot { get; set; } = "http://localhost:5000";
            public virtual string RedirectPath { get; set; } = "/signin-external";
            public virtual string Scope { get; set; } = "openid email profile";
            public virtual string StateHashSecret { get; set; } = "mysecret";

            public virtual string AuthenticationUrl { get; set; }
                = "http://localhost:5000/DemoExternalAuth/authenticate";
        }

        public class ExternalAuthHandler : IAuthenticationRequestHandler {

            public ExternalAuthHandler(IOptions<ExternalAuthOptions> options,
                    IDataProtectionProvider dp) {
                Options = options.Value;
                DataProtectionProvider = dp;
            }

            public AuthenticationScheme? Scheme { get; set; }
            public HttpContext? Context { get; set; }
            public ExternalAuthOptions Options { get; set; }
            public IDataProtectionProvider DataProtectionProvider { get; set; }
            public PropertiesDataFormat? PropertiesFormatter { get; set; }


            public Task InitializeAsync(AuthenticationScheme scheme,
                    HttpContext context) {
                Scheme = scheme;
                Context = context;
                PropertiesFormatter = new PropertiesDataFormat(DataProtectionProvider.CreateProtector(typeof(ExternalAuthOptions).FullName ?? "Unknown"));
                return Task.CompletedTask;
            }

            public Task<AuthenticateResult> AuthenticateAsync() {
                return Task.FromResult(AuthenticateResult.NoResult());
            }

            public async Task ChallengeAsync(AuthenticationProperties? properties) {
                Context?.Response.Redirect(await GetAuthenticationUrl(properties));
            }

            protected virtual Task<string>
                    GetAuthenticationUrl(AuthenticationProperties? properties) {
                Dictionary<string, string?> qs = new();
                qs.Add("client_id", Options.ClientId);
                qs.Add("redirect_uri", Options.RedirectRoot + Options.RedirectPath);
                qs.Add("scope", Options.Scope);
                qs.Add("response_type", "code");
                qs.Add("state", PropertiesFormatter!.Protect(properties!));
                return Task.FromResult(Options.AuthenticationUrl + QueryString.Create(qs));
            }

            public Task ForbidAsync(AuthenticationProperties? properties) {
                return Task.CompletedTask;
            }

            public virtual async Task<bool> HandleRequestAsync() {
                if (Context?.Request.Path.Equals(Options.RedirectPath) == true) {
                    string? authCode = await GetAuthenticationCode();
                    return true;
                }
                return false;
            }

            protected virtual Task<string?> GetAuthenticationCode() {
                return Task.FromResult(Context?.Request.Query["code"].ToString());
            }
        }
    }

***

Use the following code for `Listing 22-22`:

    using Microsoft.AspNetCore.Mvc;

    namespace ExampleApp.Controllers {

        class UserRecord {
            public string? Id { get; set; }
            public string? Name { get; set; }
            public string? EmailAddress { get; set; }
            public string? Password { get; set; }
            public string? Code { get; set; }
            public string? Token { get; set; }
        }

        public class ExternalAuthInfo {
            public string? client_id { get; set; }
            public string? client_secret { get; set; }
            public string? redirect_uri { get; set; }
            public string? scope { get; set; }
            public string? state { get; set; }
            public string? response_type { get; set; }
            public string? grant_type { get; set; }
            public string? code { get; set; }
        }


        public class DemoExternalAuthController : Controller {
            private static string expectedID = "MyClientID";
            private static string expectedSecret = "MyClientSecret";
            private static List<UserRecord> users = new List<UserRecord> {
                new UserRecord() {
                    Id = "1", Name = "Alice", EmailAddress = "alice@example.com",
                    Password = "myexternalpassword", Code = "12345", Token = "token1"
                },
                new UserRecord {
                    Id = "2", Name = "Dora", EmailAddress = "dora@example.com",
                    Password = "myexternalpassword", Code = "56789", Token = "token2"
                }
            };

            public IActionResult Authenticate([FromQuery] ExternalAuthInfo info)
            => expectedID == info.client_id ? View((info, string.Empty))
                    : View((info, "Unknown Client"));

            [HttpPost]
            public IActionResult Authenticate(ExternalAuthInfo info, string? email,
                    string? password) {
                if (string.IsNullOrEmpty(email) || string.IsNullOrEmpty(password)) {
                    ModelState.AddModelError("", "Email and password required");
                } else {
                    UserRecord? user = users.FirstOrDefault(u =>
                        u.EmailAddress?.Equals(email) == true 
                            && u.Password?.Equals(password) == true);
                    if (user != null) {
                        return Redirect(info.redirect_uri
                            + $"?code={user.Code}&scope={info.scope}"
                            + $"&state={info.state}");
                    } else {
                        ModelState.AddModelError("", "Email or password incorrect");
                    }
                }
                return View((info, ""));
            }

            [HttpPost]
            public IActionResult Exchange([FromBody] ExternalAuthInfo info) {
                UserRecord? user = users.FirstOrDefault(user => user.Code?.Equals(info.code) == true);
                if (user == null || info.client_id != expectedID
                        || info.client_secret != expectedSecret) {
                    return Json(new { error = "unauthorized_client" });
                } else {
                    return Json(new {
                        access_token = user.Token,
                        expires_in = 3600,
                        scope = "openid+email+profile",
                        token_type = "Bearer",
                        info.state
                    });
                }
            }
        }
    }

***

Use the following code for `Listing 22-23`:

    using Microsoft.AspNetCore.Authentication;
    using Microsoft.AspNetCore.Http;
    using System.Threading.Tasks;
    using System.Security.Claims;
    using Microsoft.AspNetCore.Identity;
    using Microsoft.Extensions.Options;
    using System.Collections.Generic;
    using Microsoft.AspNetCore.DataProtection;
    using System.Net.Http;
    using System.Net.Http.Json;
    using System.Text.Json;
    using Microsoft.Extensions.Logging;

    namespace ExampleApp.Custom {

        public class ExternalAuthOptions {
            public string ClientId { get; set; } = "MyClientID";
            public string ClientSecret { get; set; } = "MyClientSecret";

            public virtual string RedirectRoot { get; set; } = "http://localhost:5000";
            public virtual string RedirectPath { get; set; } = "/signin-external";
            public virtual string Scope { get; set; } = "openid email profile";
            public virtual string StateHashSecret { get; set; } = "mysecret";

            public virtual string AuthenticationUrl { get; set; }
                = "http://localhost:5000/DemoExternalAuth/authenticate";
            public virtual string ExchangeUrl { get; set; }
                = "http://localhost:5000/DemoExternalAuth/exchange";
            public virtual string ErrorUrlTemplate { get; set; }
                = "/externalsignin?error={0}";
        }

        public class ExternalAuthHandler : IAuthenticationRequestHandler {

            public ExternalAuthHandler(IOptions<ExternalAuthOptions> options,
                    IDataProtectionProvider dp, ILogger<ExternalAuthHandler> logger) {
                Options = options.Value;
                DataProtectionProvider = dp;
                Logger = logger;
            }

            public AuthenticationScheme? Scheme { get; set; }
            public HttpContext? Context { get; set; }
            public ExternalAuthOptions Options { get; set; }
            public IDataProtectionProvider DataProtectionProvider { get; set; }
            public PropertiesDataFormat? PropertiesFormatter { get; set; }
            public ILogger<ExternalAuthHandler> Logger { get; set; }
            public string? ErrorMessage { get; set; }

            public Task InitializeAsync(AuthenticationScheme scheme,
                    HttpContext context) {
                Scheme = scheme;
                Context = context;
                PropertiesFormatter = new PropertiesDataFormat(DataProtectionProvider.CreateProtector(typeof(ExternalAuthOptions).FullName ?? "Unknown"));
                return Task.CompletedTask;
            }

            public Task<AuthenticateResult> AuthenticateAsync() {
                return Task.FromResult(AuthenticateResult.NoResult());
            }

            public async Task ChallengeAsync(AuthenticationProperties? properties) {
                Context?.Response.Redirect(await GetAuthenticationUrl(properties));
            }

            protected virtual Task<string>
                    GetAuthenticationUrl(AuthenticationProperties? properties) {
                Dictionary<string, string?> qs = new();
                qs.Add("client_id", Options.ClientId);
                qs.Add("redirect_uri", Options.RedirectRoot + Options.RedirectPath);
                qs.Add("scope", Options.Scope);
                qs.Add("response_type", "code");
                qs.Add("state", PropertiesFormatter!.Protect(properties!));
                return Task.FromResult(Options.AuthenticationUrl + QueryString.Create(qs));
            }

            public Task ForbidAsync(AuthenticationProperties? properties) {
                return Task.CompletedTask;
            }

            public virtual async Task<bool> HandleRequestAsync() {
                if (Context?.Request.Path.Equals(Options.RedirectPath) == true) {
                    string? authCode = await GetAuthenticationCode();
                    (string? token, string? state) = await GetAccessToken(authCode);
                    if (!string.IsNullOrEmpty(token)) {
                        // todo - process token
                    }
                    Context.Response.Redirect(string.Format(Options.ErrorUrlTemplate,
                        ErrorMessage));
                    return true;
                }
                return false;
            }

            protected virtual Task<string?> GetAuthenticationCode() {
                return Task.FromResult(Context?.Request.Query["code"].ToString());
            }

            protected virtual async Task<(string? code, string? state)>
                    GetAccessToken(string? code) {
                string? state = Context?.Request.Query["state"];
                HttpClient httpClient = new HttpClient();
                httpClient.DefaultRequestHeaders.Add("Accept", "application/json");
                HttpResponseMessage response = await httpClient
                    .PostAsJsonAsync(Options.ExchangeUrl,
                        new {
                            code,
                            redirect_uri = Options.RedirectRoot + Options.RedirectPath,
                            client_id = Options.ClientId,
                            client_secret = Options.ClientSecret,
                            state,
                            grant_type = "authorization_code",
                        });
                string jsonData = await response.Content.ReadAsStringAsync();
                JsonDocument jsonDoc = JsonDocument.Parse(jsonData);
                string? error = jsonDoc.RootElement.GetString("error");
                if (error != null) {
                    ErrorMessage = "Access Token Error";
                    Logger.LogError(ErrorMessage);
                    Logger.LogError(jsonData);
                }
                string? token = jsonDoc.RootElement.GetString("access_token");
                string? jsonState = jsonDoc.RootElement.GetString("state") ?? state;
                return error == null ? (token, state) : (null, null);
            }
        }
    }

***

Use the following code for `Listing 22-24`:

    using Microsoft.AspNetCore.Mvc;

    namespace ExampleApp.Controllers {

        class UserRecord {
            public string? Id { get; set; }
            public string? Name { get; set; }
            public string? EmailAddress { get; set; }
            public string? Password { get; set; }
            public string? Code { get; set; }
            public string? Token { get; set; }
        }

        public class ExternalAuthInfo {
            public string? client_id { get; set; }
            public string? client_secret { get; set; }
            public string? redirect_uri { get; set; }
            public string? scope { get; set; }
            public string? state { get; set; }
            public string? response_type { get; set; }
            public string? grant_type { get; set; }
            public string? code { get; set; }
        }


        public class DemoExternalAuthController : Controller {
            private static string expectedID = "MyClientID";
            private static string expectedSecret = "MyClientSecret";
            private static List<UserRecord> users = new List<UserRecord> {
                new UserRecord() {
                    Id = "1", Name = "Alice", EmailAddress = "alice@example.com",
                    Password = "myexternalpassword", Code = "12345", Token = "token1"
                },
                new UserRecord {
                    Id = "2", Name = "Dora", EmailAddress = "dora@example.com",
                    Password = "myexternalpassword", Code = "56789", Token = "token2"
                }
            };

            public IActionResult Authenticate([FromQuery] ExternalAuthInfo info)
            => expectedID == info.client_id ? View((info, string.Empty))
                    : View((info, "Unknown Client"));

            [HttpPost]
            public IActionResult Authenticate(ExternalAuthInfo info, string? email,
                    string? password) {
                if (string.IsNullOrEmpty(email) || string.IsNullOrEmpty(password)) {
                    ModelState.AddModelError("", "Email and password required");
                } else {
                    UserRecord? user = users.FirstOrDefault(u =>
                        u.EmailAddress?.Equals(email) == true 
                            && u.Password?.Equals(password) == true);
                    if (user != null) {
                        return Redirect(info.redirect_uri
                            + $"?code={user.Code}&scope={info.scope}"
                            + $"&state={info.state}");
                    } else {
                        ModelState.AddModelError("", "Email or password incorrect");
                    }
                }
                return View((info, ""));
            }

            [HttpPost]
            public IActionResult Exchange([FromBody] ExternalAuthInfo info) {
                UserRecord? user = users.FirstOrDefault(user => user.Code?.Equals(info.code) == true);
                if (user == null || info.client_id != expectedID
                        || info.client_secret != expectedSecret) {
                    return Json(new { error = "unauthorized_client" });
                } else {
                    return Json(new {
                        access_token = user.Token,
                        expires_in = 3600,
                        scope = "openid+email+profile",
                        token_type = "Bearer",
                        info.state
                    });
                }
            }

            [HttpGet]
            public IActionResult Data([FromHeader] string authorization) {
                string? token = authorization?[7..];
                UserRecord? user = users.FirstOrDefault(user => user.Token?.Equals(token) == true);
                if (user != null) {
                    return Json(new { user.Id, user.EmailAddress, user.Name });
                } else {
                    return Json(new { error = "invalid_token" });
                }
            }
        }
    }

***

Use the following code for `Listing 22-25`:

    using Microsoft.AspNetCore.Authentication;
    using Microsoft.AspNetCore.Http;
    using System.Threading.Tasks;
    using System.Security.Claims;
    using Microsoft.AspNetCore.Identity;
    using Microsoft.Extensions.Options;
    using System.Collections.Generic;
    using Microsoft.AspNetCore.DataProtection;
    using System.Net.Http;
    using System.Net.Http.Json;
    using System.Text.Json;
    using Microsoft.Extensions.Logging;
    using System.Net.Http.Headers;

    namespace ExampleApp.Custom {

        public class ExternalAuthOptions {
            public string ClientId { get; set; } = "MyClientID";
            public string ClientSecret { get; set; } = "MyClientSecret";

            public virtual string RedirectRoot { get; set; } = "http://localhost:5000";
            public virtual string RedirectPath { get; set; } = "/signin-external";
            public virtual string Scope { get; set; } = "openid email profile";
            public virtual string StateHashSecret { get; set; } = "mysecret";

            public virtual string AuthenticationUrl { get; set; }
                = "http://localhost:5000/DemoExternalAuth/authenticate";
            public virtual string ExchangeUrl { get; set; }
                = "http://localhost:5000/DemoExternalAuth/exchange";
            public virtual string ErrorUrlTemplate { get; set; }
                = "/externalsignin?error={0}";
            public virtual string DataUrl { get; set; }
                = "http://localhost:5000/DemoExternalAuth/data";

        }

        public class ExternalAuthHandler : IAuthenticationRequestHandler {

            public ExternalAuthHandler(IOptions<ExternalAuthOptions> options,
                    IDataProtectionProvider dp, ILogger<ExternalAuthHandler> logger) {
                Options = options.Value;
                DataProtectionProvider = dp;
                Logger = logger;
            }

            public AuthenticationScheme? Scheme { get; set; }
            public HttpContext? Context { get; set; }
            public ExternalAuthOptions Options { get; set; }
            public IDataProtectionProvider DataProtectionProvider { get; set; }
            public PropertiesDataFormat? PropertiesFormatter { get; set; }
            public ILogger<ExternalAuthHandler> Logger { get; set; }
            public string? ErrorMessage { get; set; }

            public Task InitializeAsync(AuthenticationScheme scheme,
                    HttpContext context) {
                Scheme = scheme;
                Context = context;
                PropertiesFormatter = new PropertiesDataFormat(DataProtectionProvider.CreateProtector(typeof(ExternalAuthOptions).FullName ?? "Unknown"));
                return Task.CompletedTask;
            }

            public Task<AuthenticateResult> AuthenticateAsync() {
                return Task.FromResult(AuthenticateResult.NoResult());
            }

            public async Task ChallengeAsync(AuthenticationProperties? properties) {
                Context?.Response.Redirect(await GetAuthenticationUrl(properties));
            }

            protected virtual Task<string>
                    GetAuthenticationUrl(AuthenticationProperties? properties) {
                Dictionary<string, string?> qs = new();
                qs.Add("client_id", Options.ClientId);
                qs.Add("redirect_uri", Options.RedirectRoot + Options.RedirectPath);
                qs.Add("scope", Options.Scope);
                qs.Add("response_type", "code");
                qs.Add("state", PropertiesFormatter!.Protect(properties!));
                return Task.FromResult(Options.AuthenticationUrl + QueryString.Create(qs));
            }

            public Task ForbidAsync(AuthenticationProperties? properties) {
                return Task.CompletedTask;
            }

            public virtual async Task<bool> HandleRequestAsync() {
                if (Context?.Request.Path.Equals(Options.RedirectPath) == true) {
                    string? authCode = await GetAuthenticationCode();
                    (string? token, string? state) = await GetAccessToken(authCode);
                    if (!string.IsNullOrEmpty(token)) {
                        IEnumerable<Claim>? claims = await GetUserData(token);
                        if (claims != null) {
                            ClaimsIdentity identity = new ClaimsIdentity(Scheme?.Name);
                            identity.AddClaims(claims);
                            ClaimsPrincipal claimsPrincipal
                                = new ClaimsPrincipal(identity);
                            AuthenticationProperties? props
                                = PropertiesFormatter?.Unprotect(state);
                            await Context.SignInAsync(IdentityConstants.ExternalScheme,
                                claimsPrincipal, props);
                            Context.Response.Redirect(props?.RedirectUri ?? "/");
                            return true;
                        }
                    }
                    Context.Response.Redirect(string.Format(Options.ErrorUrlTemplate,
                        ErrorMessage));
                    return true;
                }
                return false;
            }

            protected virtual Task<string?> GetAuthenticationCode() {
                return Task.FromResult(Context?.Request.Query["code"].ToString());
            }

            protected virtual async Task<(string? code, string? state)>
                    GetAccessToken(string? code) {
                string? state = Context?.Request.Query["state"];
                HttpClient httpClient = new HttpClient();
                httpClient.DefaultRequestHeaders.Add("Accept", "application/json");
                HttpResponseMessage response = await httpClient
                    .PostAsJsonAsync(Options.ExchangeUrl,
                        new {
                            code,
                            redirect_uri = Options.RedirectRoot + Options.RedirectPath,
                            client_id = Options.ClientId,
                            client_secret = Options.ClientSecret,
                            state,
                            grant_type = "authorization_code",
                        });
                string jsonData = await response.Content.ReadAsStringAsync();
                JsonDocument jsonDoc = JsonDocument.Parse(jsonData);
                string? error = jsonDoc.RootElement.GetString("error");
                if (error != null) {
                    ErrorMessage = "Access Token Error";
                    Logger.LogError(ErrorMessage);
                    Logger.LogError(jsonData);
                }
                string? token = jsonDoc.RootElement.GetString("access_token");
                string? jsonState = jsonDoc.RootElement.GetString("state") ?? state;
                return error == null ? (token, state) : (null, null);
            }

            protected virtual async Task<IEnumerable<Claim>?>
            GetUserData(string accessToken) {
                HttpRequestMessage msg = new HttpRequestMessage(HttpMethod.Get,
                    Options.DataUrl);
                msg.Headers.Authorization = new AuthenticationHeaderValue("Bearer",
                    accessToken);
                HttpResponseMessage response = await new HttpClient().SendAsync(msg);
                string jsonData = await response.Content.ReadAsStringAsync();
                JsonDocument jsonDoc = JsonDocument.Parse(jsonData);

                var error = jsonDoc.RootElement.GetString("error");
                if (error != null) {
                    ErrorMessage = "User Data Error";
                    Logger.LogError(ErrorMessage);
                    Logger.LogError(jsonData);
                    return null;
                } else {
                    return GetClaims(jsonDoc);
                }
            }

            protected virtual IEnumerable<Claim> GetClaims(JsonDocument jsonDoc) {
                List<Claim> claims = new List<Claim>();
                string? val;
                if ((val = jsonDoc.RootElement.GetString("id")) != null) {
                    claims.Add(new Claim(ClaimTypes.NameIdentifier, val));
                }
                if ((val = jsonDoc.RootElement.GetString("name")) != null) {
                    claims.Add(new Claim(ClaimTypes.Name, val));
                }
                if ((val = jsonDoc.RootElement.GetString("emailAddress")) != null) {
                    claims.Add(new Claim(ClaimTypes.Email, val));
                }
                return claims;
            }
        }
    }

***

Use the following code for `Listing 22-27`:

    using ExampleApp.Identity;
    using Microsoft.AspNetCore.Identity;
    using Microsoft.AspNetCore.Mvc;
    using Microsoft.AspNetCore.Mvc.RazorPages;
    using System.Security.Claims;
    using System.Threading.Tasks;

    namespace ExampleApp.Pages {

        public class ExternalAccountConfirmModel : PageModel {

            public ExternalAccountConfirmModel(UserManager<AppUser> userManager,
                    SignInManager<AppUser> signInManager) {
                UserManager = userManager;
                SignInManager = signInManager;
            }

            public UserManager<AppUser> UserManager { get; set; }
            public SignInManager<AppUser> SignInManager { get; set; }

            public AppUser AppUser { get; set; } = new AppUser();

            public string? ProviderDisplayName { get; set; }

            [BindProperty(SupportsGet = true)]
            public string ReturnUrl { get; set; } = "/";

            public async Task<IActionResult> OnGetAsync() {
                ExternalLoginInfo info = await SignInManager.GetExternalLoginInfoAsync();
                if (info == null) {
                    return Redirect(ReturnUrl);
                } else {
                    ClaimsPrincipal external = info.Principal;
                    AppUser.EmailAddress = external.FindFirstValue(ClaimTypes.Email);
                    AppUser.UserName = external.FindFirstValue(ClaimTypes.Name);
                    ProviderDisplayName = info.ProviderDisplayName;
                    return Page();
                }
            }

            public async Task<IActionResult> OnPostAsync(string username) {
                ExternalLoginInfo info = await SignInManager.GetExternalLoginInfoAsync();

                if (info != null) {
                    ClaimsPrincipal external = info.Principal;
                    AppUser.UserName = username;
                    AppUser.EmailAddress = external.FindFirstValue(ClaimTypes.Email);
                    AppUser.EmailAddressConfirmed = true;
                    IdentityResult result = await UserManager.CreateAsync(AppUser);
                    if (result.Succeeded) {
                        await UserManager.AddClaimAsync(AppUser,
                            new Claim(ClaimTypes.Role, "User"));
                        await UserManager.AddLoginAsync(AppUser, info);
                        await SignInManager.ExternalLoginSignInAsync(info.LoginProvider,
                            info.ProviderKey, false);
                        return Redirect(ReturnUrl);
                    } else {
                        foreach (IdentityError err in result.Errors) {
                            ModelState.AddModelError(string.Empty, err.Description);
                        }
                    }
                } else {
                    ModelState.AddModelError(string.Empty, "No external login found");
                }
                return Page();
            }
        }
    }

***