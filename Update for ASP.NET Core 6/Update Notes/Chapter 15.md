# Changes for Chapter 15

## The changes required in this chapter are for null state analysis and the introduction of the minimal API for configuring ASP.NET Core applications.
***

Use the following commands for `Listing 15-2`:

    using Microsoft.AspNetCore.Authorization;
    using System.Security.Claims;

    namespace ExampleApp.Custom {
        public class AuthorizationReporter {
            private string[] schemes = new string[] { "TestScheme" };
            private RequestDelegate next;
            private IAuthorizationPolicyProvider policyProvider;
            private IAuthorizationService authorizationService;

            public AuthorizationReporter(RequestDelegate requestDelegate,
                    IAuthorizationPolicyProvider provider,
                    IAuthorizationService service) {
                next = requestDelegate;
                policyProvider = provider;
                authorizationService = service;
            }

            public async Task Invoke(HttpContext context) {
                Endpoint? ep = context.GetEndpoint();
                if (ep != null) {
                    Dictionary<(string, string), bool> results
                        = new Dictionary<(string, string), bool>();
                    bool allowAnon = ep.Metadata.GetMetadata<IAllowAnonymous>() != null;
                    IEnumerable<IAuthorizeData> authData =
                        ep?.Metadata.GetOrderedMetadata<IAuthorizeData>()
                            ?? Array.Empty<IAuthorizeData>();
                    AuthorizationPolicy? policy = await
                        AuthorizationPolicy.CombineAsync(policyProvider, authData);
                    foreach (ClaimsPrincipal cp in GetUsers()) {
                        results[(cp.Identity?.Name ?? "(No User)", cp.Identity?.AuthenticationType ?? "")] =
                                allowAnon || policy == null || await AuthorizeUser(cp, policy);
                    }
                    context.Items["authReport"] = results;
                    if (ep?.RequestDelegate != null) {
                        await ep.RequestDelegate(context);
                    }
                } else {
                    await next(context);
                }
            }

            private IEnumerable<ClaimsPrincipal> GetUsers() =>
                UsersAndClaims.GetUsers()
                    .Concat(new[] { new ClaimsPrincipal(new ClaimsIdentity()) });

            private async Task<bool> AuthorizeUser(ClaimsPrincipal cp,
                    AuthorizationPolicy policy) {
                return UserSchemeMatchesPolicySchemes(cp, policy)
                    && (await authorizationService.AuthorizeAsync(cp, policy)).Succeeded;
            }

            private bool UserSchemeMatchesPolicySchemes(ClaimsPrincipal cp,
                    AuthorizationPolicy policy) {
                return policy.AuthenticationSchemes?.Count() == 0 
                    || cp.Identities.Select(id => id.AuthenticationType).Any(auth => policy.AuthenticationSchemes != null 
                        && policy.AuthenticationSchemes.Any(scheme => scheme == auth));
            }
        }
    }

***

Ignore `Listing 15-6` and configure the application using the following code in the `Program.cs` file:

    using ExampleApp;
    using ExampleApp.Custom;
    using Microsoft.AspNetCore.Authentication.Cookies;

    var builder = WebApplication.CreateBuilder(args);

    builder.Services.AddAuthentication(opts => {
        opts.DefaultScheme
            = CookieAuthenticationDefaults.AuthenticationScheme;
    }).AddCookie(opts => {
        opts.LoginPath = "/signin";
        opts.AccessDeniedPath = "/signin/403";
    });

    builder.Services.AddAuthorization();
    builder.Services.AddRazorPages();
    builder.Services.AddControllersWithViews();
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

***

Use the following code for `Listing 15-8`:

    using Microsoft.AspNetCore.Authorization;

    namespace ExampleApp.Custom {

        public class CustomRequirement : IAuthorizationRequirement {

            public string? Name { get; set; }

        }
    }


***

Ignore `Listing 15-11` and configure the application using the following code in the `Program.cs` file:

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

    builder.Services.AddRazorPages();
    builder.Services.AddControllersWithViews();

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

***

Use the following code for `Listing 15-13`:

    using Microsoft.AspNetCore.Authorization;
    using System.Linq;
    using Microsoft.AspNetCore.Authorization.Infrastructure;

    namespace ExampleApp.Custom {

        public static class AuthorizationPolicies {

            public static void AddPolicies(AuthorizationOptions opts) {
                opts.FallbackPolicy = new AuthorizationPolicy(
                new IAuthorizationRequirement[] {
                    new RolesAuthorizationRequirement(
                        new [] { "User", "Administrator" }),
                    new AssertionRequirement(context =>
                        !string.Equals(context.User.Identity?.Name, "Bob"))
                }, Enumerable.Empty<string>());
            }
        }
    }

***

Use the following code for `Listing 15-15`:

    using Microsoft.AspNetCore.Authorization;
    using System.Linq;
    using Microsoft.AspNetCore.Authorization.Infrastructure;

    namespace ExampleApp.Custom {

        public static class AuthorizationPolicies {

            public static void AddPolicies(AuthorizationOptions opts) {
                opts.FallbackPolicy = new AuthorizationPolicy(
                new IAuthorizationRequirement[] {
                    new RolesAuthorizationRequirement(
                        new [] { "User", "Administrator" }),
                    new AssertionRequirement(context =>
                        !string.Equals(context.User.Identity?.Name, "Bob"))
                }, new string[] { "TestScheme" });
            }
        }
    }

***

Use the following code for `Listing 15-17`:

    using Microsoft.AspNetCore.Authorization;
    using System.Linq;
    using Microsoft.AspNetCore.Authorization.Infrastructure;

    namespace ExampleApp.Custom {

        public static class AuthorizationPolicies {

            public static void AddPolicies(AuthorizationOptions opts) {
                opts.FallbackPolicy = new AuthorizationPolicy(
                new IAuthorizationRequirement[] {
                    new RolesAuthorizationRequirement(
                        new [] { "User", "Administrator" }),
                    new AssertionRequirement(context =>
                        !string.Equals(context.User.Identity?.Name, "Bob"))
                }, new string[] { "TestScheme" });
                opts.DefaultPolicy = new AuthorizationPolicy(
                    new IAuthorizationRequirement[] {
                        new RolesAuthorizationRequirement(
                            new string[] { "Administrator"})
                    }, Enumerable.Empty<string>());
            }
        }
    }

***

Use the following code for `Listing 15-20`:

    using Microsoft.AspNetCore.Authorization;
    using System.Linq;
    using Microsoft.AspNetCore.Authorization.Infrastructure;

    namespace ExampleApp.Custom {

        public static class AuthorizationPolicies {

            public static void AddPolicies(AuthorizationOptions opts) {
                opts.FallbackPolicy = new AuthorizationPolicy(
                new IAuthorizationRequirement[] {
                    new RolesAuthorizationRequirement(
                        new [] { "User", "Administrator" }),
                    new AssertionRequirement(context =>
                        !string.Equals(context.User.Identity?.Name, "Bob"))
                }, new string[] { "TestScheme" });
                opts.DefaultPolicy = new AuthorizationPolicy(
                    new IAuthorizationRequirement[] {
                        new RolesAuthorizationRequirement(
                            new string[] { "Administrator"})
                    }, Enumerable.Empty<string>());
                opts.AddPolicy("UsersExceptBob", new AuthorizationPolicy(
                    new IAuthorizationRequirement[] {
                        new RolesAuthorizationRequirement(new[] { "User" }),
                        new AssertionRequirement(context =>
                            !string.Equals(context.User.Identity?.Name, "Bob"))
                    }, Enumerable.Empty<string>()));
            }
        }
    }

***

Use the following code for `Listing 15-22`:

    using Microsoft.AspNetCore.Authorization;
    using System.Linq;
    using Microsoft.AspNetCore.Authorization.Infrastructure;

    namespace ExampleApp.Custom {

        public static class AuthorizationPolicies {

            public static void AddPolicies(AuthorizationOptions opts) {
                opts.FallbackPolicy = new AuthorizationPolicy(
                new IAuthorizationRequirement[] {
                    new RolesAuthorizationRequirement(
                        new [] { "User", "Administrator" }),
                    new AssertionRequirement(context =>
                        !string.Equals(context.User.Identity?.Name, "Bob"))
                }, new string[] { "TestScheme" });
                opts.DefaultPolicy = new AuthorizationPolicy(
                    new IAuthorizationRequirement[] {
                        new RolesAuthorizationRequirement(
                            new string[] { "Administrator"})
                    }, Enumerable.Empty<string>());
                opts.AddPolicy("UsersExceptBob", new AuthorizationPolicy(
                    new IAuthorizationRequirement[] {
                        new RolesAuthorizationRequirement(new[] { "User" }),
                        new AssertionRequirement(context =>
                            !string.Equals(context.User.Identity?.Name, "Bob"))
                    }, Enumerable.Empty<string>()));
                opts.AddPolicy("UsersExceptBob", builder => builder.RequireRole("User")
                    .AddRequirements(new AssertionRequirement(context =>
                        !string.Equals(context.User.Identity?.Name, "Bob")))
                    .AddAuthenticationSchemes("OtherScheme"));
            }
        }
    }

***

Use the following code for `Listing 15-25`:

using Microsoft.AspNetCore.Authorization;
using System.Linq;
using Microsoft.AspNetCore.Authorization.Infrastructure;

namespace ExampleApp.Custom {

    public static class AuthorizationPolicies {

        public static void AddPolicies(AuthorizationOptions opts) {
            opts.FallbackPolicy = new AuthorizationPolicy(
               new IAuthorizationRequirement[] {
                   new RolesAuthorizationRequirement(
                       new [] { "User", "Administrator" }),
                   new AssertionRequirement(context =>
                       !string.Equals(context.User.Identity?.Name, "Bob"))
               }, new string[] { "TestScheme" });
            opts.DefaultPolicy = new AuthorizationPolicy(
                new IAuthorizationRequirement[] {
                    new RolesAuthorizationRequirement(
                        new string[] { "Administrator"})
                }, Enumerable.Empty<string>());
            opts.AddPolicy("UsersExceptBob", new AuthorizationPolicy(
                new IAuthorizationRequirement[] {
                    new RolesAuthorizationRequirement(new[] { "User" }),
                    new AssertionRequirement(context =>
                        !string.Equals(context.User.Identity?.Name, "Bob"))
                }, Enumerable.Empty<string>()));
            opts.AddPolicy("UsersExceptBob", builder => builder.RequireRole("User")
                .AddRequirements(new AssertionRequirement(context =>
                    !string.Equals(context.User.Identity?.Name, "Bob")))
                .AddAuthenticationSchemes("OtherScheme"));
            opts.AddPolicy("NotAdmins", builder =>
                builder.AddRequirements(new AssertionRequirement(context =>
                    !context.User.IsInRole("Administrator"))));
        }
    }
}

***

Ignore `Listing 15-26` and configure the application using the following code in the `Program.cs` file:

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

    builder.Services.AddControllersWithViews();

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

***

Use the following code for `Listing 15-28`:

    using Microsoft.AspNetCore.Authorization;
    using Microsoft.AspNetCore.Mvc.ApplicationModels;

    namespace ExampleApp.Custom {

        public class AuthorizationPolicyConvention : IActionModelConvention {
            private string controllerName;
            private string? actionName;
            private IAuthorizeData attr = new AuthData();

            public AuthorizationPolicyConvention(string controller,
                    string? action = null, string? policy = null,
                    string? roles = null, string ?schemes = null) {
                controllerName = controller;
                actionName = action;
                attr.Policy = policy;
                attr.Roles = roles;
                attr.AuthenticationSchemes = schemes;
            }

            public void Apply(ActionModel action) {
                if (controllerName == action.Controller.ControllerName
                        && (actionName == null || actionName == action.ActionName)) {
                    foreach (var s in action.Selectors) {
                        s.EndpointMetadata.Add(attr);
                    }
                }
            }
        }

        class AuthData : IAuthorizeData {
            public string? AuthenticationSchemes { get; set; }
            public string? Policy { get; set; }
            public string? Roles { get; set; }
        }
    }

***

Ignore `Listing 15-29` and configure the application using the following code in the `Program.cs` file:

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

***