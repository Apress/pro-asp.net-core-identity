using ExampleApp.Custom;
using Microsoft.AspNetCore.Authentication.Cookies;
using Microsoft.AspNetCore.Authorization;

var builder = WebApplication.CreateBuilder(args);

builder.Services.AddTransient<IAuthorizationHandler,
    CustomRequirementHandler>();

builder.Services.AddAuthentication(opts => {
    opts.DefaultScheme
        = CookieAuthenticationDefaults.AuthenticationScheme;
}).AddCookie(opts => {
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
