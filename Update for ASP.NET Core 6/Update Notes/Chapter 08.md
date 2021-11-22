# Changes for Chapter 8

## The changes required in this chapter are for null state analysis and the introduction of the minimal API for configuring ASP.NET Core applications.
***

Use the following code for `Listing 8-5`:

    using System.ComponentModel.DataAnnotations;
    using System.Threading.Tasks;
    using Microsoft.AspNetCore.Identity;
    using Microsoft.AspNetCore.Mvc;
    using SignInResult = Microsoft.AspNetCore.Identity.SignInResult;

    namespace IdentityApp.Pages.Identity {

        public class SignInModel : UserPageModel {

            public SignInModel(SignInManager<IdentityUser> signMgr)
                => SignInManager = signMgr;

            public SignInManager<IdentityUser> SignInManager { get; set; }

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

Use the following content for `Listing 8-6`:

    @page
    @model IdentityApp.Pages.Identity.SignOutModel
    @{
        ViewData["showNav"] = false;
        ViewData["banner"] = "Sign Out";
    }

    @if (User.Identity?.IsAuthenticated == true) {
        <form method="post">
            <div class="text-center">
                <h6>Click the button to sign out of the application</h6>
                <button type="submit" class="btn btn-secondary">
                    Sign Out
                </button>
            </div>
        </form>
    } else {
        <div class="text-center">
            <h6>You are signed out of the application</h6>
            <a asp-page="SignIn" asp-route-returnUrl="" class="btn btn-secondary">
                OK
            </a>
        </div>    
    }

***

Use the following content for `Listing 8-9`:

    <nav class="nav">
        @if (User.Identity?.IsAuthenticated == true) { 
            <a asp-page="/Identity/Index" class="nav-link bg-secondary text-white">
                    @User.Identity.Name
            </a>
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

Ignore `Listing 8-10` and configure the application using the following code in the `Program.cs` file:

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
    }).AddEntityFrameworkStores<IdentityDbContext>();

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

    var app = builder.Build();

    app.UseHttpsRedirection();
    app.UseStaticFiles();

    app.UseAuthentication();
    app.UseAuthorization();

    app.MapDefaultControllerRoute();
    app.MapRazorPages();

    app.Run();

***

Use the following code for `Listing 8-11`:

    using Microsoft.AspNetCore.Identity;
    using System.Threading.Tasks;

    namespace IdentityApp.Pages.Identity {

        public class IndexModel : UserPageModel {

            public IndexModel(UserManager<IdentityUser> userMgr)
                => UserManager = userMgr;

            public UserManager<IdentityUser> UserManager { get; set; }

            public string Email { get; set; } = string.Empty;
            public string Phone { get; set; } = string.Empty;

            public async Task OnGetAsync() {
                IdentityUser CurrentUser = await UserManager.GetUserAsync(User);
                Email = CurrentUser?.Email ?? "(No Value)";
                Phone = CurrentUser?.PhoneNumber ?? "(No Value)";
            }
        }
    }

***

Use the following code for `Listing 8-13`:

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
        }
    }

***


Ignore `Listing 8-14` and configure the application using the following code in the `Program.cs` file:

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

    var app = builder.Build();

    app.UseHttpsRedirection();
    app.UseStaticFiles();

    app.UseAuthentication();
    app.UseAuthorization();

    app.MapDefaultControllerRoute();
    app.MapRazorPages();

    app.Run();

***

Use the following code for `Listing 8-16`:

    using Microsoft.AspNetCore.Identity;
    using Microsoft.AspNetCore.Mvc;
    using System.ComponentModel.DataAnnotations;

    namespace IdentityApp.Pages.Identity {

        public class PasswordChangeBindingTarget {
            [Required]
            public string? Current { get; set; }

            [Required]
            public string? NewPassword { get; set; }

            [Required]
            [Compare(nameof(NewPassword))]
            public string? ConfirmPassword { get; set; }
        }

        public class UserPasswordChangeModel : UserPageModel {

            public UserPasswordChangeModel(UserManager<IdentityUser> usrMgr)
                => UserManager = usrMgr;

            public UserManager<IdentityUser> UserManager { get; set; }

            public async Task<IActionResult> OnPostAsync(
                    PasswordChangeBindingTarget data) {
                if (ModelState.IsValid) {
                    IdentityUser user = await UserManager.GetUserAsync(User);
                    IdentityResult result = await UserManager.ChangePasswordAsync(user,
                        data.Current, data.NewPassword);
                    if (result.Process(ModelState)) {
                        TempData["message"] = "Password changed";
                        return RedirectToPage();
                    }
                }
                return Page();
            }
        }
    }

***

Use the following code for `Listing 8-18`:

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
        }
    }

***

Use the following code for `Listing 8-22`:

    using IdentityApp.Services;
    using Microsoft.AspNetCore.Identity;
    using Microsoft.AspNetCore.Mvc;
    using System.ComponentModel.DataAnnotations;
    using System.Threading.Tasks;

    namespace IdentityApp.Pages.Identity {

        public class UserPasswordRecoveryConfirmModel : UserPageModel {

            public UserPasswordRecoveryConfirmModel(UserManager<IdentityUser> usrMgr,
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
                        TempData["message"] = "Password changed";
                        return RedirectToPage();
                    }
                }
                return Page();
            }
        }
    }

***

Use the following code for `Listing 8-25`:

    using IdentityApp.Services;
    using Microsoft.AspNetCore.Identity;
    using Microsoft.AspNetCore.Mvc;
    using System.ComponentModel.DataAnnotations;

    namespace IdentityApp.Pages.Identity.Admin {

        public class PasswordsModel : AdminPageModel {

            public PasswordsModel(UserManager<IdentityUser> usrMgr,
                    IdentityEmailService emailService) {
                UserManager = usrMgr;
                EmailService = emailService;
            }

            public UserManager<IdentityUser> UserManager { get; set; }
            public IdentityEmailService EmailService { get; set; }

            public IdentityUser IdentityUser { get; set; } = new();

            [BindProperty(SupportsGet = true)]
            public string? Id { get; set; }

            [BindProperty]
            [Required]
            public string? Password { get; set; }

            [BindProperty]
            [Compare(nameof(Password))]
            public string? Confirmation { get; set; }

            public async Task<IActionResult> OnGetAsync() {
                if (string.IsNullOrEmpty(Id)) {
                    return RedirectToPage("Selectuser",
                        new { Label = "Password", Callback = "Passwords" });
                }
                IdentityUser = await UserManager.FindByIdAsync(Id);
                return Page();
            }

            public async Task<IActionResult> OnPostSetPasswordAsync() {
                if (ModelState.IsValid) {
                    IdentityUser = await UserManager.FindByIdAsync(Id);
                    if (await UserManager.HasPasswordAsync(IdentityUser)) {
                        await UserManager.RemovePasswordAsync(IdentityUser);
                    }
                    IdentityResult result =
                        await UserManager.AddPasswordAsync(IdentityUser, Password);
                    if (result.Process(ModelState)) {
                        TempData["message"] = "Password Changed";
                        return RedirectToPage();
                    }
                }
                return Page();
            }

            public async Task<IActionResult> OnPostUserChangeAsync() {
                IdentityUser = await UserManager.FindByIdAsync(Id);
                await UserManager.RemovePasswordAsync(IdentityUser);
                await EmailService.SendPasswordRecoveryEmail(IdentityUser,
                    "/Identity/UserPasswordRecoveryConfirm");
                TempData["message"] = "Email Sent to User";
                return RedirectToPage();
            }
        }
    }


***