# Changes for Chapter 21

## The changes required in this chapter are for null state analysis and the introduction of the minimal API for configuring ASP.NET Core applications.

***

Ignore `Listing 21-1` and configure the application using the following code in the `Program.cs` file:

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

Use the following code for `Listing 21-3`:

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
            public bool AuthenticatorEnabled { get; set; }
            public string? AuthenticatorKey { get; set; }

        }
    }

***

Use the following code for `Listing 21-4`:

    using Microsoft.AspNetCore.Identity;

    namespace ExampleApp.Identity.Store {
        public partial class UserStore : IUserAuthenticatorKeyStore<AppUser> {

            public Task<string?> GetAuthenticatorKeyAsync(AppUser user,
                    CancellationToken cancellationToken)
                => Task.FromResult(user.AuthenticatorKey);

            public Task SetAuthenticatorKeyAsync(AppUser user, string key,
                    CancellationToken cancellationToken) {
                user.AuthenticatorKey = key;
                return Task.CompletedTask;
            }
        }
    }

***

Ignore `Listing 21-11` and configure the application using the following code in the `Program.cs` file:

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

Use the following code for `Listing 21-13`:

    namespace ExampleApp.Identity.Store {

        public class RecoveryCode {

            public string Code { get; set; } = String.Empty;
            public bool Redeemed { get; set; }
        }
    }

***

Use the following code for `Listing 21-14`:

    using Microsoft.AspNetCore.Identity;
    using System;
    using System.Collections.Generic;
    using System.Linq;
    using System.Threading;
    using System.Threading.Tasks;

    namespace ExampleApp.Identity.Store {

        public interface IReadableUserTwoFactorRecoveryCodeStore
                : IUserTwoFactorRecoveryCodeStore<AppUser> {
            Task<IEnumerable<RecoveryCode>> GetCodesAsync(AppUser user);
        }

        public partial class UserStore : IReadableUserTwoFactorRecoveryCodeStore {
            private IDictionary<string, IEnumerable<RecoveryCode>> recoveryCodes
                = new Dictionary<string, IEnumerable<RecoveryCode>>();

            public async Task<int> CountCodesAsync(AppUser user, CancellationToken token)
                => (await GetCodesAsync(user)).Where(code => !code.Redeemed).Count();


            public Task<IEnumerable<RecoveryCode>> GetCodesAsync(AppUser user) =>
                Task.FromResult(recoveryCodes.ContainsKey(user.Id)
                    ? recoveryCodes[user.Id] : Enumerable.Empty<RecoveryCode>());

            public async Task<bool> RedeemCodeAsync(AppUser user, string code,
                    CancellationToken token) {
                RecoveryCode rc = (await GetCodesAsync(user))
                    .FirstOrDefault(rc => rc.Code == code && !rc.Redeemed);
                if (rc != null) {
                    rc.Redeemed = true;
                    return true;
                }
                return false;
            }

            public Task ReplaceCodesAsync(AppUser user, IEnumerable<string>
                    recoveryCodes, CancellationToken token) {
                this.recoveryCodes[user.Id] = recoveryCodes
                    .Select(rc => new RecoveryCode { Code = rc, Redeemed = false });
                return Task.CompletedTask;
            }
        }
    }

***

Use the following code for `Listing 21-17`:

    using ExampleApp.Identity;
    using ExampleApp.Identity.Store;
    using Microsoft.AspNetCore.Identity;
    using Microsoft.AspNetCore.Mvc;
    using Microsoft.AspNetCore.Mvc.RazorPages;

    namespace ExampleApp.Pages.Store {

        public class RecoveryCodesModel : PageModel {

            public RecoveryCodesModel(UserManager<AppUser> manager,
                    IUserStore<AppUser> store) {
                UserManager = manager;
                UserStore = store;
            }

            public UserManager<AppUser> UserManager { get; set; }
            public IUserStore<AppUser> UserStore { get; set; }

            public AppUser AppUser { get; set; } = new();

            public RecoveryCode[] Codes { get; set; } = new RecoveryCode[0];
            public int RemainingCodes { get; set; }

            public async Task OnGetAsync(string id) {
                AppUser = await UserManager.FindByIdAsync(id);
                if (AppUser != null) {
                    Codes = (await GetCodes()).OrderBy(c => c.Code).ToArray();
                    RemainingCodes = await UserManager.CountRecoveryCodesAsync(AppUser);
                }
            }

            public async Task<IActionResult> OnPostAsync(string id) {
                AppUser = await UserManager.FindByIdAsync(id);
                await UserManager.GenerateNewTwoFactorRecoveryCodesAsync(AppUser, 10);
                return RedirectToPage();
            }

            private async Task<IEnumerable<RecoveryCode>> GetCodes() {
                if (UserStore is IReadableUserTwoFactorRecoveryCodeStore) {
                    return await (UserStore as IReadableUserTwoFactorRecoveryCodeStore)!.GetCodesAsync(AppUser);
                }
                return Enumerable.Empty<RecoveryCode>();
            }
        }
    }

***

Use the following code for `Listing 21-18`:

    @model AppUser
    @inject UserManager<AppUser> UserManager

    @if (UserManager.SupportsUserTwoFactor) {
        <tr>
            <td>Two-Factor</td>
            <td><input asp-for="TwoFactorEnabled"/></td>
        </tr>
    }
    @if (UserManager.SupportsUserTwoFactorRecoveryCodes) {
        <tr>
            <td>Recovery Codes</td>
            <td>
                @(await UserManager.CountRecoveryCodesAsync(Model)) codes remaining
                    <a asp-page="RecoveryCodes" asp-route-id="@Model?.Id" 
                    class="btn btn-sm btn-secondary align-top">Change</a>
            </td>
        </tr>
    }

***