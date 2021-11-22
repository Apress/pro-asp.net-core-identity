# Changes for Chapter 9

## The changes required in this chapter are for null state analysis and the introduction of the minimal API for configuring ASP.NET Core applications.
***

Use the following code for `Listing 9-4`:

    using IdentityApp.Services;
    using Microsoft.AspNetCore.Identity;
    using Microsoft.AspNetCore.Mvc;
    using System.ComponentModel.DataAnnotations;
    using System.Threading.Tasks;

    namespace IdentityApp.Pages.Identity.Admin {

        public class CreateModel : AdminPageModel {

            public CreateModel(UserManager<IdentityUser> mgr,
                IdentityEmailService emailService) {
                UserManager = mgr;
                EmailService = emailService;
            }

            public UserManager<IdentityUser> UserManager { get; set; }
            public IdentityEmailService EmailService { get; set; }

            [BindProperty(SupportsGet = true)]
            [EmailAddress]
            public string Email { get; set; }  = string.Empty;

            public async Task<IActionResult> OnPostAsync() {
                if (ModelState.IsValid) {
                    IdentityUser user = new IdentityUser {
                        UserName = Email,
                        Email = Email,
                        EmailConfirmed = true
                    };
                    IdentityResult result = await UserManager.CreateAsync(user);
                    if (result.Process(ModelState)) {
                        await EmailService.SendPasswordRecoveryEmail(user,
                            "/Identity/UserAccountComplete");
                        TempData["message"] = "Account Created";
                        return RedirectToPage();
                    }
                }
                return Page();
            }
        }
    }

***

Use the following code for `Listing 9-6`:

    using IdentityApp.Services;
    using Microsoft.AspNetCore.Authorization;
    using Microsoft.AspNetCore.Identity;
    using Microsoft.AspNetCore.Mvc;
    using System.ComponentModel.DataAnnotations;

    namespace IdentityApp.Pages.Identity {

        [AllowAnonymous]
        public class UserAccountCompleteModel : UserPageModel {

            public UserAccountCompleteModel(UserManager<IdentityUser> usrMgr,
                    TokenUrlEncoderService tokenUrlEncoder) {
                UserManager = usrMgr;
                TokenUrlEncoder = tokenUrlEncoder;
            }

            public UserManager<IdentityUser> UserManager { get; set; }
            public TokenUrlEncoderService TokenUrlEncoder { get; set; }

            [BindProperty(SupportsGet = true)]
            public string? Email { get; set; }

            [BindProperty(SupportsGet = true)]
            public string? Token { get; set; }

            [BindProperty]
            [Required]
            public string? Password { get; set; }

            [BindProperty]
            [Required]
            [Compare(nameof(Password))]
            public string? ConfirmPassword { get; set; }

            public async Task<IActionResult> OnPostAsync() {
                if (ModelState.IsValid && Token != null) {
                    IdentityUser user = await UserManager.FindByEmailAsync(Email);
                    string decodedToken = TokenUrlEncoder.DecodeToken(Token);
                    IdentityResult result = await UserManager.ResetPasswordAsync(user,
                        decodedToken, Password);
                    if (result.Process(ModelState)) {
                        return RedirectToPage("SignIn", new { });
                    }
                }
                return Page();
            }
        }
    }

***

Use the following code for `Listing 9-8`:

    using Microsoft.AspNetCore.Identity;
    using Microsoft.AspNetCore.Identity.UI.Services;

    namespace IdentityApp.Services {

        public class IdentityEmailService {

            public IdentityEmailService(IEmailSender sender,
                    UserManager<IdentityUser> userMgr,
                    IHttpContextAccessor contextAccessor,
                    LinkGenerator generator,
                    TokenUrlEncoderService encoder) {
                EmailSender = sender;
                UserManager = userMgr;
                ContextAccessor = contextAccessor;
                LinkGenerator = generator;
                TokenEncoder = encoder;
            }

            public IEmailSender EmailSender { get; set; }
            public UserManager<IdentityUser> UserManager { get; set; }
            public IHttpContextAccessor ContextAccessor { get; set; }
            public LinkGenerator LinkGenerator { get; set; }
            public TokenUrlEncoderService TokenEncoder { get; set; }

            private string? GetUrl(string emailAddress, string token, string page) {
                string safeToken = TokenEncoder.EncodeToken(token);
                if (ContextAccessor.HttpContext != null) {
                    return LinkGenerator.GetUriByPage(ContextAccessor.HttpContext, page,
                        null, new { email = emailAddress, token = safeToken });
                }
                return null;
            }

            public async Task SendPasswordRecoveryEmail(IdentityUser user,
                    string confirmationPage) {
                string token = await UserManager.GeneratePasswordResetTokenAsync(user);
                string? url = GetUrl(user.Email, token, confirmationPage);
                await EmailSender.SendEmailAsync(user.Email, "Set Your Password",
                    $"Please set your password by <a href={url}>clicking here</a>.");
            }

            public async Task SendAccountConfirmEmail(IdentityUser user,
                    string confirmationPage) {
                string token = await UserManager.GenerateEmailConfirmationTokenAsync(user);
                string? url = GetUrl(user.Email, token, confirmationPage);
                await EmailSender.SendEmailAsync(user.Email,
                    "Complete Your Account Setup",
                    $"Please set up your account by <a href={url}>clicking here</a>.");
            }
        }
    }

***

Use the following code for `Listing 9-10`:

    using IdentityApp.Services;
    using Microsoft.AspNetCore.Authorization;
    using Microsoft.AspNetCore.Identity;
    using Microsoft.AspNetCore.Mvc;
    using System.ComponentModel.DataAnnotations;
    using System.Threading.Tasks;

    namespace IdentityApp.Pages.Identity {

        [AllowAnonymous]
        public class SignUpModel : UserPageModel {

            public SignUpModel(UserManager<IdentityUser> usrMgr,
                    IdentityEmailService emailService) {
                UserManager = usrMgr;
                EmailService = emailService;
            }

            public UserManager<IdentityUser> UserManager { get; set; }
            public IdentityEmailService EmailService { get; set; }

            [BindProperty]
            [Required]
            [EmailAddress]
            public string? Email { get; set; }

            [BindProperty]
            [Required]
            public string? Password { get; set; }

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

Use the following code for `Listing 9-12`:

    using Microsoft.AspNetCore.Authorization;
    using Microsoft.AspNetCore.Identity;
    using Microsoft.AspNetCore.Mvc;
    using Microsoft.AspNetCore.WebUtilities;
    using System.Text;
    using System.Threading.Tasks;

    namespace IdentityApp.Pages.Identity {

        [AllowAnonymous]
        public class SignUpConfirmModel : UserPageModel {

            public SignUpConfirmModel(UserManager<IdentityUser> usrMgr)
                => UserManager = usrMgr;

            public UserManager<IdentityUser> UserManager { get; set; }

            [BindProperty(SupportsGet = true)]
            public string? Email { get; set; }

            [BindProperty(SupportsGet = true)]
            public string? Token { get; set; }

            public bool ShowConfirmedMessage { get; set; } = false;

            public async Task<IActionResult> OnGetAsync() {
                if (!string.IsNullOrEmpty(Email) && !string.IsNullOrEmpty(Token)) {
                    IdentityUser user = await UserManager.FindByEmailAsync(Email);
                    if (user != null) {
                        string decodedToken = Encoding.UTF8.GetString(
                            WebEncoders.Base64UrlDecode(Token));
                        IdentityResult result =
                            await UserManager.ConfirmEmailAsync(user, decodedToken);
                        if (result.Process(ModelState)) {
                            ShowConfirmedMessage = true;
                        }
                    }
                }
                return Page();
            }
        }
    }

***

Use the following code for `Listing 9-14`:

    using IdentityApp.Services;
    using Microsoft.AspNetCore.Authorization;
    using Microsoft.AspNetCore.Identity;
    using Microsoft.AspNetCore.Mvc;
    using System.ComponentModel.DataAnnotations;

    namespace IdentityApp.Pages.Identity {

        [AllowAnonymous]
        public class SignUpResendModel : UserPageModel {

            public SignUpResendModel(UserManager<IdentityUser> usrMgr,
                IdentityEmailService emailService) {
                UserManager = usrMgr;
                EmailService = emailService;
            }

            public UserManager<IdentityUser> UserManager { get; set; }
            public IdentityEmailService EmailService { get; set; }

            [EmailAddress]
            [BindProperty(SupportsGet = true)]
            public string? Email { get; set; }

            public async Task<IActionResult> OnPostAsync() {
                if (ModelState.IsValid) {
                    IdentityUser user = await UserManager.FindByEmailAsync(Email);
                    if (user != null && !await UserManager.IsEmailConfirmedAsync(user)) {
                        await EmailService.SendAccountConfirmEmail(user,
                            "SignUpConfirm");
                    }
                    TempData["message"] = "Confirmation email sent. Check your inbox.";
                    return RedirectToPage(new { Email });
                }
                return Page();
            }
        }
    }

***

Use the following code for `Listing 9-15`:

    using System.ComponentModel.DataAnnotations;
    using System.Threading.Tasks;
    using Microsoft.AspNetCore.Identity;
    using Microsoft.AspNetCore.Mvc;
    using SignInResult = Microsoft.AspNetCore.Identity.SignInResult;
    using Microsoft.AspNetCore.Authorization;

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
        }
    }

***

Use the following code for `Listing 9-19`:

    using Microsoft.AspNetCore.Identity;
    using Microsoft.AspNetCore.Mvc;

    namespace IdentityApp.Pages.Identity.Admin {

        public class LockoutsModel : AdminPageModel {

            public LockoutsModel(UserManager<IdentityUser> usrMgr)
                => UserManager = usrMgr;

            public UserManager<IdentityUser> UserManager { get; set; }

            public IEnumerable<IdentityUser> LockedOutUsers { get; set; } = Enumerable.Empty<IdentityUser>();
            public IEnumerable<IdentityUser> OtherUsers { get; set; } = Enumerable.Empty<IdentityUser>();

            public async Task<TimeSpan> TimeLeft(IdentityUser user)
                => (await UserManager.GetLockoutEndDateAsync(user))
                    .GetValueOrDefault().Subtract(DateTimeOffset.Now);

            public void OnGet() {
                LockedOutUsers = UserManager.Users.Where(user => user.LockoutEnd.HasValue
                        && user.LockoutEnd.Value > DateTimeOffset.Now)
                    .OrderBy(user => user.Email).ToList();
                OtherUsers = UserManager.Users.Where(user => !user.LockoutEnd.HasValue
                        || user.LockoutEnd.Value <= DateTimeOffset.Now)
                    .OrderBy(user => user.Email).ToList();
            }

            public async Task<IActionResult> OnPostLockAsync(string id) {
                IdentityUser user = await UserManager.FindByIdAsync(id);
                await UserManager.SetLockoutEnabledAsync(user, true);
                await UserManager.SetLockoutEndDateAsync(user,
                    DateTimeOffset.Now.AddDays(5));
                return RedirectToPage();
            }

            public async Task<IActionResult> OnPostUnlockAsync(string id) {
                IdentityUser user = await UserManager.FindByIdAsync(id);
                await UserManager.SetLockoutEndDateAsync(user, null);
                return RedirectToPage();
            }
        }
    }

***

Ignore `Listing 9-21` and configure the application using the following code in the `Program.cs` file:

    using Microsoft.EntityFrameworkCore;
    using IdentityApp.Models;
    using Microsoft.AspNetCore.Identity;
    using Microsoft.AspNetCore.Identity.EntityFrameworkCore;
    using Microsoft.AspNetCore.Identity.UI.Services;
    using IdentityApp.Services;

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

    app.Run();

***

Use the following code for `Listing 9-25`:

    using Microsoft.AspNetCore.Identity;
    using Microsoft.AspNetCore.Mvc;

    namespace IdentityApp.Pages.Identity.Admin {

        public class DeleteModel : AdminPageModel {

            public DeleteModel(UserManager<IdentityUser> mgr) => UserManager = mgr;

            public UserManager<IdentityUser> UserManager { get; set; }

            public IdentityUser IdentityUser { get; set; } = new();

            [BindProperty(SupportsGet = true)]
            public string? Id { get; set; }

            public async Task<IActionResult> OnGetAsync() {
                if (string.IsNullOrEmpty(Id)) {
                    return RedirectToPage("Selectuser",
                        new { Label = "Delete", Callback = "Delete" });
                }
                IdentityUser = await UserManager.FindByIdAsync(Id);
                return Page();
            }

            public async Task<IActionResult> OnPostAsync() {
                IdentityUser = await UserManager.FindByIdAsync(Id);
                IdentityResult result = await UserManager.DeleteAsync(IdentityUser);
                if (result.Process(ModelState)) {
                    return RedirectToPage("Dashboard");
                }
                return Page();
            }
        }
    }

***