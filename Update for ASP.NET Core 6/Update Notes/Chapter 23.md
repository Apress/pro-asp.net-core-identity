# Changes for Chapter 23

## The changes required in this chapter are for null state analysis and the introduction of the minimal API for configuring ASP.NET Core applications. 

***

Ignore `Listing 23-1` and configure the application using the following code in the `Program.cs` file:

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
    //builder.Services.AddSingleton<IUserValidator<AppUser>, EmailValidator>();
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

Use the following code for `Listing 23-3`:

    using Microsoft.AspNetCore.Mvc;

    namespace ExampleApp.Controllers {

        [ApiController]
        [Route("api/[controller]")]
        public class DemoExternalApiController : Controller {

            private Dictionary<string, string> data
                = new Dictionary<string, string> {
                    { "token1", "This is Alice's external data" },
                    { "token2", "This is Dora's external data" },
                };

            [HttpGet]
            public IActionResult GetData([FromHeader] string authorization) {
                if (!string.IsNullOrEmpty(authorization)) {
                    string? token = authorization?[7..];
                    if (!string.IsNullOrEmpty(token) && data.ContainsKey(token)) {
                        return Json(new { data = data[token] });
                    }
                }
                return NotFound();
            }
        }
    }

***

Use the following code for `Listing 23-4`:

    using System.Security.Claims;
    using Microsoft.AspNetCore.Identity;
    using Microsoft.AspNetCore.Authentication;

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

            public IList<(string provider, AuthenticationToken token)> AuthTokens { get; set; } 
                = new List<(string, AuthenticationToken)>();

        }
    }


***

Use the following code for `Listing 23-5`:

    using Microsoft.AspNetCore.Authentication;
    using Microsoft.AspNetCore.Identity;

    namespace ExampleApp.Identity.Store {
        public partial class UserStore : IUserAuthenticationTokenStore<AppUser> {

            public Task<string?> GetTokenAsync(AppUser user, string loginProvider,
                    string name, CancellationToken cancelToken) {
                return Task.FromResult(user.AuthTokens?
                    .FirstOrDefault(t => t.provider == loginProvider
                        && t.token.Name == name).token.Value);
            }

            public Task RemoveTokenAsync(AppUser user, string loginProvider,
                    string name, CancellationToken cancelToken) {
                if (user.AuthTokens != null) {
                    user.AuthTokens = user.AuthTokens.Where(t =>
                        t.provider != loginProvider
                            && t.token.Name != name).ToList();
                }
                return Task.CompletedTask;
            }

            public Task SetTokenAsync(AppUser user, string loginProvider,
                string name, string value, CancellationToken cancelToken) {
                if (user.AuthTokens == null) {
                    user.AuthTokens = new List<(string, AuthenticationToken)>();
                }
                user.AuthTokens.Add((loginProvider, new AuthenticationToken {
                    Name = name, Value = value
                }));
                return Task.CompletedTask;
            }
        }
    }

***

Use the following code for `Listing 23-6`:

    ...
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
                    props?.StoreTokens(new[] { new AuthenticationToken {
                        Name = "access_token", Value = token } });
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
    ...

***

Use the following code for `Listing 23-7`:

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
                await SignInManager.UpdateExternalAuthenticationTokensAsync(info);
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

Use the following code for `Listing 23-8`:

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
                        await SignInManager.UpdateExternalAuthenticationTokensAsync(info);
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

Use the following code for `Listing 23-10`:

    using ExampleApp.Identity;
    using Microsoft.AspNetCore.Authentication;
    using Microsoft.AspNetCore.Identity;
    using Microsoft.AspNetCore.Mvc.RazorPages;
    using System.Net.Http.Headers;
    using System.Text.Json;

    namespace ExampleApp.Pages {

        public class ApiDataModel : PageModel {

            public ApiDataModel(UserManager<AppUser> userManager) {
                UserManager = userManager;
            }

            public UserManager<AppUser> UserManager { get; set; }

            public string Data { get; set; } = "No Data";

            public async Task OnGetAsync() {
                AppUser user = await UserManager.GetUserAsync(HttpContext.User);
                if (user != null) {
                    string token = await UserManager.GetAuthenticationTokenAsync
                        (user, "demoAuth", "access_token");
                    if (!string.IsNullOrEmpty(token)) {
                        HttpRequestMessage msg = new HttpRequestMessage(
                            HttpMethod.Get,
                            "http://localhost:5000/api/DemoExternalApi");
                        msg.Headers.Authorization = new AuthenticationHeaderValue
                            ("Bearer", token);
                        HttpResponseMessage resp
                            = await new HttpClient().SendAsync(msg);
                        JsonDocument doc = JsonDocument.Parse(await
                            resp.Content.ReadAsStringAsync());
                        Data = doc.RootElement.GetString("data") ?? "No Data";
                    }
                }
            }
        }
    }

***

Use the following code for `Listing 23-11`:


    using Microsoft.AspNetCore.Authentication;
    using Microsoft.AspNetCore.DataProtection;
    using Microsoft.Extensions.Options;
    using System.Security.Claims;
    using System.Text.Json;

    namespace ExampleApp.Custom {

        public class GoogleOptions : ExternalAuthOptions {
            public override string RedirectPath { get; set; } = "/signin-google";
            public override string AuthenticationUrl =>
                "https://accounts.google.com/o/oauth2/v2/auth";
            public override string ExchangeUrl =>
                "https://www.googleapis.com/oauth2/v4/token";
            public override string DataUrl =>
                "https://www.googleapis.com/oauth2/v2/userinfo";
        }

        public class GoogleHandler : ExternalAuthHandler {

            public GoogleHandler(IOptions<GoogleOptions> options,
                IDataProtectionProvider dp,
                ILogger<GoogleHandler> logger) : base(options, dp, logger) { }

            protected override IEnumerable<Claim> GetClaims(JsonDocument jsonDoc) {
                List<Claim> claims = new List<Claim>();
                string? value;
                if ((value = jsonDoc.RootElement.GetString("id")) != null) {
                    claims.Add(new Claim(ClaimTypes.NameIdentifier, value));
                }
                if ((value = jsonDoc.RootElement.GetString("name")) != null) {
                    claims.Add(new Claim(ClaimTypes.Name, value));
                }
                if ((value = jsonDoc.RootElement.GetString("email")) != null) {
                    claims.Add(new Claim(ClaimTypes.Email, value));
                }
                return claims;
            }

            protected async override Task<string> GetAuthenticationUrl(
                    AuthenticationProperties? properties) {
                if (CheckCredentials()) {
                    return await base.GetAuthenticationUrl(properties);
                } else {
                    return string.Format(Options.ErrorUrlTemplate, ErrorMessage);
                }
            }

            private bool CheckCredentials() {
                string secret = Options.ClientSecret;
                string id = Options.ClientId;
                string defaultVal = "ReplaceMe";
                if (string.IsNullOrEmpty(secret) || string.IsNullOrEmpty(id)
                    || defaultVal.Equals(secret) || defaultVal.Equals(secret)) {
                    ErrorMessage = "External Authentication Secret or ID Not Set";
                    Logger.LogError("External Authentication Secret or ID Not Set");
                    return false;
                }
                return true;
            }
        }
    }

***

Ignore `Listing 23-12` and configure the application using the following code in the `Program.cs` file:

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
    //builder.Services.AddSingleton<IUserValidator<AppUser>, EmailValidator>();
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

    builder.Services.Configure<GoogleOptions>(opts => {
        opts.ClientId = "ReplaceMe";
        opts.ClientSecret = "ReplaceMe";
    });

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
        opts.AddScheme<GoogleHandler>("google", "Google");
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

Use the following code for `Listing 23-13`:

    using Microsoft.AspNetCore.Authentication;
    using Microsoft.AspNetCore.DataProtection;
    using Microsoft.Extensions.Options;
    using System.Security.Claims;
    using System.Text.Json;

    namespace ExampleApp.Custom {

        public class FacebookOptions : ExternalAuthOptions {
            public override string RedirectPath { get; set; } = "/signin-facebook";
            public override string Scope { get; set; } = "email";

            public override string AuthenticationUrl =>
                "https://www.facebook.com/v8.0/dialog/oauth";
            public override string ExchangeUrl =>
                "https://graph.facebook.com/v8.0/oauth/access_token";
            public override string DataUrl =>
                "https://graph.facebook.com/v8.0/me?fields=name,email";
        }

        public class FacebookHandler : ExternalAuthHandler {

            public FacebookHandler(IOptions<FacebookOptions> options,
                IDataProtectionProvider dp,
                ILogger<FacebookHandler> logger) : base(options, dp, logger) {

                string secret = Options.ClientSecret;
                if (string.IsNullOrEmpty(secret) || "MyClientSecret"
                        .Equals(secret, StringComparison.OrdinalIgnoreCase)) {
                    logger.LogError("External Authentication Secret Not Set");
                }
            }

            protected override IEnumerable<Claim> GetClaims(JsonDocument jsonDoc) {
                List<Claim> claims = new List<Claim>();
                string? value;
                if ((value = jsonDoc.RootElement.GetString("id")) != null) {
                    claims.Add(new Claim(ClaimTypes.NameIdentifier, value));
                }
                if ((value = jsonDoc.RootElement.GetString("name")) != null) {
                    claims.Add(new Claim(ClaimTypes.Name, value.Replace(" ", "_")));
                }

                if ((value = jsonDoc.RootElement.GetString("email")) != null) {
                    claims.Add(new Claim(ClaimTypes.Email, value));
                }
                return claims;
            }
        }
    }

***

Ignore `Listing 23-14` and configure the application using the following code in the `Program.cs` file:

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
    //builder.Services.AddSingleton<IUserValidator<AppUser>, EmailValidator>();
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

    builder.Services.Configure<GoogleOptions>(opts => {
        opts.ClientId = "ReplaceMe";
        opts.ClientSecret = "ReplaceMe";
    });

    builder.Services.Configure<FacebookOptions>(opts => {
        opts.ClientId = "ReplaceMe";
        opts.ClientSecret = "ReplaceMe";
    });

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
        opts.AddScheme<GoogleHandler>("google", "Google");
        opts.AddScheme<FacebookHandler>("facebook", "Facebook");
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

Use the following code for `Listing 23-16`:

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

            public async Task<IActionResult> OnPost(string username,
                    [FromQuery] string returnUrl) {
                AppUser user = await UserManager.FindByEmailAsync(username);
                UserLoginInfo? loginInfo = user?.UserLogins?.FirstOrDefault();
                if (loginInfo != null) {
                    return RedirectToPage("/ExternalSignIn", new {
                        returnUrl, providerName = loginInfo.LoginProvider
                    });
                }
                return RedirectToPage("SignInPassword", new { username, returnUrl });
            }
        }
    }

***

Use the following code for `Listing 23-17`:

    @page
    @model ExampleApp.Pages.SignInPasswordModel

    <div asp-validation-summary="All" class="text-danger m-2"></div>

    <form method="post" class="p-2">
        <input type="hidden" name="returnUrl" value="@Model.ReturnUrl" />
        <div class="form-group">
            <label>User</label>
            <input class="form-control" readonly name="username" 
                value="@Model.Username" />
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
            <a class="btn btn-secondary" href="/password/reset">
                Reset Password
            </a>
        }
    </form>

***

Use the following code for `Listing 23-18`:

    using ExampleApp.Identity;
    using Microsoft.AspNetCore.Identity;
    using Microsoft.AspNetCore.Mvc;
    using Microsoft.AspNetCore.Mvc.RazorPages;
    using SignInResult = Microsoft.AspNetCore.Identity.SignInResult;

    namespace ExampleApp.Pages {

        public class SignInPasswordModel : PageModel {

            public SignInPasswordModel(UserManager<AppUser> userManager,
                    SignInManager<AppUser> signInManager) {
                UserManager = userManager;
                SignInManager = signInManager;
            }

            public UserManager<AppUser> UserManager { get; set; }
            public SignInManager<AppUser> SignInManager { get; set; }

            public string? Username { get; set; }
            public string? ReturnUrl { get; set; }

            public void OnGet(string username, string returnUrl) {
                Username = username;
                ReturnUrl = returnUrl;
            }

            public async Task<ActionResult> OnPost(string username,
                    string password, string returnUrl) {
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
                        ModelState.AddModelError("",
                            $"Locked Out for {remaining.Minutes} mins and"
                                + $" {remaining.Seconds} secs");
                    } else if (result.RequiresTwoFactor) {
                        return RedirectToPage("/SignInTwoFactor", new { returnUrl });
                    } else if (result.IsNotAllowed) {
                        ModelState.AddModelError("", "Sign In Not Allowed");
                    } else {
                        ModelState.AddModelError("", "Access Denied");
                    }
                    Username = username;
                    ReturnUrl = returnUrl;
                    return Page();
                }
                return Redirect(returnUrl ?? "/signin");
            }
        }
    }

***

Use the following code for `Listing 23-19`:

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


            public IActionResult OnGet(string error, string providerName, string returnUrl)
                => error == null ? OnPost(providerName, returnUrl) : Page();

            public IActionResult OnPost(string providerName, string returnUrl = "/") {
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
                await SignInManager.UpdateExternalAuthenticationTokensAsync(info);
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

Use the following code for `Listing 23-20`:

    ...
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
                UserLoginInfo? firstLogin = user?.UserLogins?.FirstOrDefault();
                if (firstLogin != null
                        && firstLogin.LoginProvider != info.LoginProvider) {
                    return RedirectToPage(
                        new {
                            error =
                            $"{firstLogin.ProviderDisplayName} Authentication Expected"
                        });
                } else {
                    await UserManager.AddLoginAsync(user!, info);
                }
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
    ...

***
