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
