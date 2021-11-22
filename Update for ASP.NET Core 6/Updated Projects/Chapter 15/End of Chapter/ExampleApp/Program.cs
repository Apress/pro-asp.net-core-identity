using ExampleApp;
using ExampleApp.Custom;
using Microsoft.AspNetCore.Authentication.Cookies;
using Microsoft.AspNetCore.Authorization;

var builder = WebApplication.CreateBuilder(args);

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

builder.Services.AddRazorPages(opts => {
    opts.Conventions.AuthorizePage("/Secret", "NotAdmins");
});

builder.Services.AddControllersWithViews(opts => {
    opts.Conventions.Add(new AuthorizationPolicyConvention("Home",
        policy: "NotAdmins"));
    opts.Conventions.Add(new AuthorizationPolicyConvention("Home",
        action: "Protected", policy: "UsersExceptBob"));
});

builder.Services.AddTransient<IAuthorizationHandler, CustomRequirementHandler>();

var app = builder.Build();

app.UseStaticFiles();

app.UseAuthentication();

//app.UseMiddleware<RoleMemberships>();
app.UseMiddleware<ClaimsReporter>();

//app.UseAuthorization();
app.UseMiddleware<AuthorizationReporter>();

app.MapGet("/", async context => {
    await context.Response.WriteAsync("Hello World!");
});
//app.MapGet("/secret", SecretEndpoint.Endpoint)
//    .WithDisplayName("secret");
app.MapRazorPages();
app.MapDefaultControllerRoute();

app.Run();
