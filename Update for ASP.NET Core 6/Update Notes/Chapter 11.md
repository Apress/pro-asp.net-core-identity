# Changes for Chapter 11

## The changes required in this chapter are for null state analysis and the introduction of the minimal API for configuring ASP.NET Core applications.
***

Use the following code for `Listing 11-4`:

    using Microsoft.AspNetCore.Identity;
    using Microsoft.AspNetCore.Mvc;
    using System.Threading.Tasks;

    namespace IdentityApp.Pages.Identity {

        public class UserTwoFactorManageModel : UserPageModel {

            public UserTwoFactorManageModel(UserManager<IdentityUser> usrMgr,
                    SignInManager<IdentityUser> signMgr) { 
                UserManager = usrMgr;
                SignInManager = signMgr;
            }

            public UserManager<IdentityUser> UserManager { get; set; }
            public SignInManager<IdentityUser> SignInManager { get; set; }

            public IdentityUser IdentityUser { get; set; }


            public async Task<bool> IsTwoFactorEnabled()
                => await UserManager.GetTwoFactorEnabledAsync(IdentityUser);

            public async Task OnGetAsync() {
                IdentityUser = await UserManager.GetUserAsync(User);
            }

            public async Task<IActionResult> OnPostDisable() {
                IdentityUser = await UserManager.GetUserAsync(User);
                IdentityResult result = await 
                    UserManager.SetTwoFactorEnabledAsync(IdentityUser, false);
                if (result.Process(ModelState)) {
                    await SignInManager.SignOutAsync();
                    return RedirectToPage("Index", new { });
                }
                return Page();
            }

            public async Task<IActionResult> OnPostGenerateCodes() {
                IdentityUser = await UserManager.GetUserAsync(User);
                TempData["RecoveryCodes"] = 
                    await UserManager.GenerateNewTwoFactorRecoveryCodesAsync(
                        IdentityUser, 10);
                return RedirectToPage("UserRecoveryCodes");
            }
        }
    }

***

Use the following code for `Listing 11-6`:

    using Microsoft.AspNetCore.Identity;
    using Microsoft.AspNetCore.Mvc;
    using System.ComponentModel.DataAnnotations;
    using System.Text.RegularExpressions;

    namespace IdentityApp.Pages.Identity {

        public class UserTwoFactorSetupModel : UserPageModel {

            public UserTwoFactorSetupModel(UserManager<IdentityUser> usrMgr,
                SignInManager<IdentityUser> signMgr) {
                UserManager = usrMgr;
                SignInManager = signMgr;
            }

            public UserManager<IdentityUser> UserManager { get; set; }
            public SignInManager<IdentityUser> SignInManager { get; set; }

            public IdentityUser IdentityUser { get; set; } = new();

            public string? AuthenticatorKey { get; set; }

            public string? QrCodeUrl { get; set; }

            public async Task<IActionResult> OnGet() {
                await LoadAuthenticatorKeys();
                if (await UserManager.GetTwoFactorEnabledAsync(IdentityUser)) {
                    return RedirectToPage("UserTwoFactorManage");
                }
                return Page();
            }

            public async Task<IActionResult> OnPostConfirm([Required] string confirm) {
                await LoadAuthenticatorKeys();
                if (ModelState.IsValid) {
                    string token = Regex.Replace(confirm, @"\s", "");
                    bool codeValid = await
                            UserManager.VerifyTwoFactorTokenAsync(IdentityUser,
                        UserManager.Options.Tokens.AuthenticatorTokenProvider, token);
                    if (codeValid) {
                        TempData["RecoveryCodes"] = await UserManager
                            .GenerateNewTwoFactorRecoveryCodesAsync(IdentityUser, 10);
                        await UserManager.SetTwoFactorEnabledAsync(IdentityUser, true);
                        await SignInManager.RefreshSignInAsync(IdentityUser);
                        return RedirectToPage("UserRecoveryCodes");
                    } else {
                        ModelState.AddModelError(string.Empty,
                            "Confirmation code invalid");
                    }
                }
                return Page();
            }

            private async Task LoadAuthenticatorKeys() {
                IdentityUser = await UserManager.GetUserAsync(User);
                AuthenticatorKey =
                    await UserManager.GetAuthenticatorKeyAsync(IdentityUser);
                if (AuthenticatorKey == null) {
                    await UserManager.ResetAuthenticatorKeyAsync(IdentityUser);
                    AuthenticatorKey =
                        await UserManager.GetAuthenticatorKeyAsync(IdentityUser);
                    await SignInManager.RefreshSignInAsync(IdentityUser);
                }
                QrCodeUrl = $"otpauth://totp/ExampleApp:{IdentityUser.Email}"
                            + $"?secret={AuthenticatorKey}";
            }
        }
    }

***

Use the following content for `Listing 11-7`:

    @page
    @model IdentityApp.Pages.Identity.UserRecoveryCodesModel
    @{
        ViewBag.Workflow = "TwoFactor";
    }

    <h4 class="text-center">Recovery Codes</h4>

    <h6>
        These recovery codes can be used to sign in if you don't have your authenticator.
        Store these codes in a safe place. You won't be able to view them again.
        Each code can only be used once.
    </h6>

    <table class="table table-sm table-striped">
        <tbody>
            @for (int i = 0; i < Model.RecoveryCodes?.Length; i +=2 ) {
                <tr>
                    <td><code>@Model.RecoveryCodes[i]</code></td>
                    <td><code>@Model.RecoveryCodes[i + 1]</code></td>
                </tr>
            }
        </tbody>
    </table>
    <a asp-page="UserTwoFactorManage" class="btn btn-primary">OK</a>

***

Use the following code for `Listing 11-8`:

    using Microsoft.AspNetCore.Mvc;

    namespace IdentityApp.Pages.Identity {

        public class UserRecoveryCodesModel : UserPageModel {

            [TempData]
            public string[]? RecoveryCodes { get; set; }

            public IActionResult OnGet() {
                if (RecoveryCodes == null || RecoveryCodes.Length == 0) {
                    return RedirectToPage("UserTwoFactorManage");
                }
                return Page();
            }
        }
    }

***

Use the following code for `Listing 11-12`:

    using Microsoft.AspNetCore.Authorization;
    using Microsoft.AspNetCore.Identity;
    using Microsoft.AspNetCore.Mvc;
    using System.ComponentModel.DataAnnotations;
    using System.Text.RegularExpressions;
    using SignInResult = Microsoft.AspNetCore.Identity.SignInResult;

    namespace IdentityApp.Pages.Identity {

        [AllowAnonymous]
        public class SignInTwoFactorModel : UserPageModel {

            public SignInTwoFactorModel(UserManager<IdentityUser> usrMgr,
                    SignInManager<IdentityUser> signMgr) {
                UserManager = usrMgr;
                SignInManager = signMgr;
            }

            public UserManager<IdentityUser> UserManager { get; set; }
            public SignInManager<IdentityUser> SignInManager { get; set; }

            [BindProperty]
            public string? ReturnUrl { get; set; }

            [BindProperty]
            [Required]
            public string? Token { get; set; }

            [BindProperty]
            public bool RememberMe { get; set; }

            public async Task<IActionResult> OnPostAsync() {
                if (ModelState.IsValid) {
                    IdentityUser user = await
                        SignInManager.GetTwoFactorAuthenticationUserAsync();
                    if (user != null && Token != null) {
                        string token = Regex.Replace(Token, @"\s", "");
                        SignInResult result = await
                            SignInManager.TwoFactorAuthenticatorSignInAsync(token, true,
                                RememberMe);
                        if (!result.Succeeded) {
                            result = await
                                SignInManager.TwoFactorRecoveryCodeSignInAsync(token);
                        }
                        if (result.Succeeded) {
                            if (await UserManager.CountRecoveryCodesAsync(user) <= 3) {
                                return RedirectToPage("SignInCodesWarning");
                            }
                            return Redirect(ReturnUrl ?? "/");
                        }
                    }
                    ModelState.AddModelError("", "Invalid token or recovery code");
                }
                return Page();
            }
        }
    }

***

Ignore `Listing 11-15` and configure the application using the following code in the `Program.cs` file:

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
            opts.RetrieveUserDetails = true;
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

Use the following code for `Listing 11-17`:

    using IdentityApp.Services;
    using Microsoft.AspNetCore.Authorization;
    using Microsoft.AspNetCore.Identity;
    using Microsoft.AspNetCore.Mvc;
    using System.ComponentModel.DataAnnotations;
    using Microsoft.AspNetCore.Authentication;

    namespace IdentityApp.Pages.Identity {

        [AllowAnonymous]
        public class SignUpModel : UserPageModel {

            public SignUpModel(UserManager<IdentityUser> usrMgr,
                    IdentityEmailService emailService,
                    SignInManager<IdentityUser> signMgr) {
                UserManager = usrMgr;
                EmailService = emailService;
                SignInManager = signMgr;
            }

            public UserManager<IdentityUser> UserManager { get; set; }
            public IdentityEmailService EmailService { get; set; }
            public SignInManager<IdentityUser> SignInManager { get; set; }

            [BindProperty]
            [Required]
            [EmailAddress]
            public string? Email { get; set; }

            [BindProperty]
            [Required]
            public string? Password { get; set; }

            public IEnumerable<AuthenticationScheme> ExternalSchemes { get; set; } = Enumerable.Empty<AuthenticationScheme>();  


            public async Task OnGetAsync() {
                ExternalSchemes = await
                    SignInManager.GetExternalAuthenticationSchemesAsync();
            }

            public async Task<IActionResult> OnPostAsync() {
                if (ModelState.IsValid) {
                    IdentityUser user = await UserManager.FindByEmailAsync(Email);
                    if (user != null && !await UserManager.IsEmailConfirmedAsync(user)) {
                        return RedirectToPage("SignUpConfirm");
                    }
                    user = new IdentityUser {
                        UserName = Email,
                        Email = Email
                    };
                    IdentityResult result = await UserManager.CreateAsync(user);
                    if (result.Process(ModelState)) {
                        result = await UserManager.AddPasswordAsync(user, Password);
                        if (result.Process(ModelState)) {
                            await EmailService.SendAccountConfirmEmail(user,
                                "SignUpConfirm");
                            return RedirectToPage("SignUpConfirm");
                        } else {
                            await UserManager.DeleteAsync(user);
                        }
                    }
                }
                return Page();
            }
        }
    }

***

Use the following code for `Listing 11-19`:

    using Microsoft.AspNetCore.Authentication;
    using Microsoft.AspNetCore.Authorization;
    using Microsoft.AspNetCore.Identity;
    using Microsoft.AspNetCore.Mvc;
    using System.Security.Claims;

    namespace IdentityApp.Pages.Identity {

        [AllowAnonymous]
        public class SignUpExternalModel : UserPageModel {

            public SignUpExternalModel(UserManager<IdentityUser> usrMgr,
                    SignInManager<IdentityUser> signMgr) {
                UserManager = usrMgr;
                SignInManager = signMgr;
            }

            public UserManager<IdentityUser> UserManager { get; set; }
            public SignInManager<IdentityUser> SignInManager { get; set; }

            public IdentityUser IdentityUser { get; set; } = new();

            public async Task<string?> ExternalProvider() =>
                (await UserManager.GetLoginsAsync(IdentityUser))
                .FirstOrDefault()?.ProviderDisplayName;


            public IActionResult OnPost(string provider) {
                string? callbackUrl = Url.Page("SignUpExternal", "Callback");
                AuthenticationProperties props =
                SignInManager.ConfigureExternalAuthenticationProperties(
                    provider, callbackUrl);
                return new ChallengeResult(provider, props);
            }

            public async Task<IActionResult> OnGetCallbackAsync() {
                ExternalLoginInfo info = await SignInManager.GetExternalLoginInfoAsync();

                string? email = info?.Principal?.FindFirst(ClaimTypes.Email)?.Value;
                if (string.IsNullOrEmpty(email)) {
                    return Error("External service has not provided an email address.");
                } else if ((await UserManager.FindByEmailAsync(email)) != null) {
                    return Error("An account already exists with your email address.");
                }

                IdentityUser identUser = new IdentityUser {
                    UserName = email,
                    Email = email,
                    EmailConfirmed = true
                };
                IdentityResult result = await UserManager.CreateAsync(identUser);
                if (result.Succeeded) {
                    identUser = await UserManager.FindByEmailAsync(email);
                    result = await UserManager.AddLoginAsync(identUser, info);
                    return RedirectToPage(new { id = identUser.Id });
                }
                return Error("An account could not be created.");
            }

            public async Task<IActionResult> OnGetAsync(string id) {
                if (id == null) {
                    return RedirectToPage("SignUp");
                } else {
                    IdentityUser = await UserManager.FindByIdAsync(id);
                    if (IdentityUser == null) {
                        return RedirectToPage("SignUp");
                    }
                }
                return Page();
            }

            private IActionResult Error(string err) {
                TempData["errorMessage"] = err;
                return RedirectToPage();
            }
        }
    }

***

Use the following code for `Listing 11-22`:

    using IdentityApp.Services;
    using Microsoft.AspNetCore.Authentication;
    using Microsoft.AspNetCore.Authorization;
    using Microsoft.AspNetCore.Identity;
    using Microsoft.AspNetCore.Mvc;
    using System.Security.Claims;

    namespace IdentityApp.Pages.Identity {

        [AllowAnonymous]
        public class UserAccountCompleteExternalModel : UserPageModel {

            public UserAccountCompleteExternalModel(
                    UserManager<IdentityUser> usrMgr,
                    SignInManager<IdentityUser> signMgr,
                    TokenUrlEncoderService encoder) {
                UserManager = usrMgr;
                SignInManager = signMgr;
                TokenUrlEncoder = encoder;
            }

            public UserManager<IdentityUser> UserManager { get; set; }
            public SignInManager<IdentityUser> SignInManager { get; set; }
            public TokenUrlEncoderService TokenUrlEncoder { get; set; }

            [BindProperty(SupportsGet = true)]
            public string? Email { get; set; }

            [BindProperty(SupportsGet = true)]
            public string Token { get; set; } = String.Empty;

            public IdentityUser IdentityUser { get; set; } = new();

            public async Task<string?> ExternalProvider() =>
                (await UserManager.GetLoginsAsync(IdentityUser))
                    .FirstOrDefault()?.ProviderDisplayName;

            public async Task<IActionResult> OnPostAsync(string provider) {
                IdentityUser = await UserManager.FindByEmailAsync(Email);
                string decodedToken = TokenUrlEncoder.DecodeToken(Token);
                bool valid = await UserManager.VerifyUserTokenAsync(IdentityUser,
                    UserManager.Options.Tokens.PasswordResetTokenProvider,
                    UserManager<IdentityUser>.ResetPasswordTokenPurpose, decodedToken);
                if (!valid) {
                    return Error("Invalid token");
                }
                string? callbackUrl = Url.Page("UserAccountCompleteExternal",
                    "Callback", new { Email, Token });
                AuthenticationProperties props =
                SignInManager.ConfigureExternalAuthenticationProperties(
                    provider, callbackUrl);
                return new ChallengeResult(provider, props);
            }

            public async Task<IActionResult> OnGetCallbackAsync() {
                ExternalLoginInfo info = await SignInManager.GetExternalLoginInfoAsync();
                string? email = info?.Principal?.FindFirst(ClaimTypes.Email)?.Value;
                if (string.IsNullOrEmpty(email)) {
                    return Error("External service has not provided an email address.");
                } else if ((IdentityUser =
                        await UserManager.FindByEmailAsync(email)) == null) {
                    return Error("Your email address doesn't match.");
                }
                IdentityResult result
                    = await UserManager.AddLoginAsync(IdentityUser, info);
                if (!result.Succeeded) {
                    return Error("Cannot store external login.");
                }
                return RedirectToPage(new { id = IdentityUser.Id });
            }

            public async Task<IActionResult> OnGetAsync(string id) {
                if ((id == null
                    || (IdentityUser = await UserManager.FindByIdAsync(id)) == null)
                    && !TempData.ContainsKey("errorMessage")) {
                    return RedirectToPage("SignIn");
                }
                return Page();
            }

            private IActionResult Error(string err) {
                TempData["errorMessage"] = err;
                return RedirectToPage();
            }
        }
    }

***

Use the following code for `Listing 11-24`:

    using System.ComponentModel.DataAnnotations;
    using System.Threading.Tasks;
    using Microsoft.AspNetCore.Identity;
    using Microsoft.AspNetCore.Mvc;
    using SignInResult = Microsoft.AspNetCore.Identity.SignInResult;
    using Microsoft.AspNetCore.Authorization;
    using Microsoft.AspNetCore.Authentication;
    using System.Net;

    namespace IdentityApp.Pages.Identity {

        [AllowAnonymous]
        public class SignInModel : UserPageModel {

            public SignInModel(SignInManager<IdentityUser> signMgr,
                    UserManager<IdentityUser> usrMgr) {
                SignInManager = signMgr;
                UserManager = usrMgr;
            }

            public SignInManager<IdentityUser> SignInManager { get; set; }
            public UserManager<IdentityUser> UserManager { get; set; }

            [Required]
            [EmailAddress]
            [BindProperty]
            public string? Email { get; set; }

            [Required]
            [BindProperty]
            public string? Password { get; set; }

            [BindProperty(SupportsGet = true)]
            public string? ReturnUrl { get; set; }

            public async Task<IActionResult> OnPostAsync() {
                if (ModelState.IsValid) {
                    SignInResult result = await SignInManager.PasswordSignInAsync(Email,
                        Password, true, true);
                    if (result.Succeeded) {
                        return Redirect(ReturnUrl ?? "/");
                    } else if (result.IsLockedOut) {
                        TempData["message"] = "Account Locked";
                    } else if (result.IsNotAllowed) {
                        TempData["message"] = "Sign In Not Allowed";
                        IdentityUser user = await UserManager.FindByEmailAsync(Email);
                        if (user != null &&
                            !await UserManager.IsEmailConfirmedAsync(user)) {
                            return RedirectToPage("SignUpConfirm");
                        }
                    } else if (result.RequiresTwoFactor) {
                        return RedirectToPage("SignInTwoFactor", new { ReturnUrl });
                    } else {
                        TempData["message"] = "Sign In Failed";
                    }
                }
                return Page();
            }

            public IActionResult OnPostExternalAsync(string provider) {
                string? callbackUrl = Url.Page("SignIn", "Callback", new { ReturnUrl });
                AuthenticationProperties props =
                SignInManager.ConfigureExternalAuthenticationProperties(
                    provider, callbackUrl);
                return new ChallengeResult(provider, props);
            }

            public async Task<IActionResult> OnGetCallbackAsync() {
                ExternalLoginInfo info = await SignInManager.GetExternalLoginInfoAsync();
                SignInResult result = await SignInManager.ExternalLoginSignInAsync(
                    info.LoginProvider, info.ProviderKey, true);
                if (result.Succeeded) {
                    return Redirect(WebUtility.UrlDecode(ReturnUrl ?? "/"));
                } else if (result.IsLockedOut) {
                    TempData["message"] = "Account Locked";
                } else if (result.IsNotAllowed) {
                    TempData["message"] = "Sign In Not Allowed";
                } else {
                    TempData["message"] = "Sign In Failed";
                }
                return RedirectToPage();
            }
        }
    }

***