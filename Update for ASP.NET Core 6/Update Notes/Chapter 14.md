# Changes for Chapter 14

## The changes required in this chapter are the introduction of the minimal API for configuring ASP.NET Core applications. This includes nullable type annotations applied to the Identity API.
***

Use the following commands for `Listing 14-2`:

    using ExampleApp;

    var builder = WebApplication.CreateBuilder(args);


    var app = builder.Build();

    app.MapGet("/", async context => {
        await context.Response.WriteAsync("Hello World!");
    });
    app.MapGet("/secret", SecretEndpoint.Endpoint)
        .WithDisplayName("secret");

    app.Run();

***

Use the following commands for `Listing 14-5`:

    using System.Security.Claims;

    namespace ExampleApp.Custom {
        public class ClaimsReporter {
            private RequestDelegate next;

            public ClaimsReporter(RequestDelegate requestDelegate)
                    => next = requestDelegate;

            public async Task Invoke(HttpContext context) {

                ClaimsPrincipal p = context.User;

                Console.WriteLine($"User: {p.Identity?.Name}");
                Console.WriteLine($"Authenticated: {p.Identity?.IsAuthenticated}");
                Console.WriteLine("Authentication Type "
                    + p.Identity?.AuthenticationType);

                Console.WriteLine($"Identities: {p.Identities.Count()}");
                foreach (ClaimsIdentity ident in p.Identities) {
                    Console.WriteLine($"Auth type: {ident.AuthenticationType},"
                        + $" {ident.Claims.Count()} claims");
                    foreach (Claim claim in ident.Claims) {
                        Console.WriteLine($"Type: {GetName(claim.Type)}, "
                            + $"Value: {claim.Value}, Issuer: {claim.Issuer}");
                    }
                }
                await next(context);
            }

            private string GetName(string claimType) =>
                Path.GetFileName(new Uri(claimType).LocalPath);
        }
    }

***

Ignore `Listing 14-6` and configure the application using the following code in the `Program.cs` file:

    using ExampleApp;
    using ExampleApp.Custom;

    var builder = WebApplication.CreateBuilder(args);

    var app = builder.Build();

    app.UseMiddleware<CustomAuthentication>();
    app.UseMiddleware<ClaimsReporter>();

    app.MapGet("/", async context => {
        await context.Response.WriteAsync("Hello World!");
    });
    app.MapGet("/secret", SecretEndpoint.Endpoint)
        .WithDisplayName("secret");

    app.Run();

***

Use the following code for `Listing 14-8`:

    using Microsoft.AspNetCore.Http;
    using System.Security.Claims;
    using System.Security.Principal;
    using System.Threading.Tasks;

    namespace ExampleApp.Custom {

        public class RoleMemberships {
            private RequestDelegate next;

            public RoleMemberships(RequestDelegate requestDelegate)
                    => next = requestDelegate;

            public async Task Invoke(HttpContext context) {
                IIdentity? mainIdent = context.User.Identity;
                if (mainIdent?.IsAuthenticated == true && mainIdent.Name != null 
                        && UsersAndClaims.Claims.ContainsKey(mainIdent.Name)) {
                    ClaimsIdentity ident = new ClaimsIdentity("Roles");
                    ident.AddClaim(new Claim(ClaimTypes.Name, mainIdent.Name));
                    ident.AddClaims(UsersAndClaims.Claims[mainIdent.Name]);
                    context.User.AddIdentity(ident);
                }
                await next(context);
            }
        }
    }

***

Ignore `Listing 14-9` and configure the application using the following code in the `Program.cs` file:

    using ExampleApp;
    using ExampleApp.Custom;

    var builder = WebApplication.CreateBuilder(args);

    var app = builder.Build();

    app.UseMiddleware<CustomAuthentication>();
    app.UseMiddleware<RoleMemberships>();
    app.UseMiddleware<ClaimsReporter>();

    app.MapGet("/", async context => {
        await context.Response.WriteAsync("Hello World!");
    });
    app.MapGet("/secret", SecretEndpoint.Endpoint)
        .WithDisplayName("secret");

    app.Run();

***

Use the following code for `Listing 14-10`:

    using Microsoft.AspNetCore.Http;
    using System.Threading.Tasks;

    namespace ExampleApp.Custom {

        public class CustomAuthorization {
            private RequestDelegate next;

            public CustomAuthorization(RequestDelegate requestDelegate)
                    => next = requestDelegate;

            public async Task Invoke(HttpContext context) {
                if (context.GetEndpoint()?.DisplayName == "secret") {
                    if (context.User.Identity?.IsAuthenticated == true) {
                        if (context.User.IsInRole("Administrator")) {
                            await next(context);
                        } else {
                            Forbid(context);
                        }
                    } else {
                        Challenge(context);
                    }
                } else {
                    await next(context);
                }
            }

            public void Challenge(HttpContext context)
                    => context.Response.StatusCode = StatusCodes.Status401Unauthorized;

            public void Forbid(HttpContext context)
                    => context.Response.StatusCode = StatusCodes.Status403Forbidden;
        }
    }

***

Ignore `Listing 14-11` and configure the application using the following code in the `Program.cs` file:

    using ExampleApp;
    using ExampleApp.Custom;

    var builder = WebApplication.CreateBuilder(args);

    var app = builder.Build();

    app.UseMiddleware<CustomAuthentication>();
    app.UseMiddleware<RoleMemberships>();
    app.UseMiddleware<ClaimsReporter>();
    app.UseMiddleware<CustomAuthorization>();

    app.MapGet("/", async context => {
        await context.Response.WriteAsync("Hello World!");
    });
    app.MapGet("/secret", SecretEndpoint.Endpoint)
        .WithDisplayName("secret");

    app.Run();

***

Ignore `Listing 14-13` and configure the application using the following code in the `Program.cs` file:

    using ExampleApp;
    using ExampleApp.Custom;

    var builder = WebApplication.CreateBuilder(args);

    var app = builder.Build();

    app.UseMiddleware<CustomAuthentication>();
    app.UseMiddleware<RoleMemberships>();
    app.UseMiddleware<ClaimsReporter>();
    app.UseMiddleware<CustomAuthorization>();

    app.MapGet("/", async context => {
        await context.Response.WriteAsync("Hello World!");
    });
    app.MapGet("/secret", SecretEndpoint.Endpoint)
        .WithDisplayName("secret");
    app.Map("/signin", CustomSignInAndSignOut.SignIn);
    app.Map("/signout", CustomSignInAndSignOut.SignOut);

    app.Run();

***
Use the following code for `Listing 14-14`:

    using Microsoft.AspNetCore.Http;
    using System.Security.Claims;
    using System.Threading.Tasks;

    namespace ExampleApp.Custom {

        public class CustomAuthentication {
            private RequestDelegate next;

            public CustomAuthentication(RequestDelegate requestDelegate)
                    => next = requestDelegate;

            public async Task Invoke(HttpContext context) {
                //string user = context.Request.Query["user"];
                string? user = context.Request.Cookies["authUser"];
                if (user != null) {
                    Claim claim = new Claim(ClaimTypes.Name, user);
                    ClaimsIdentity ident = new ClaimsIdentity("QueryStringValue");
                    ident.AddClaim(claim);
                    context.User = new ClaimsPrincipal(ident);
                }
                await next(context);
            }
        }
    }

***

Use the following code for `Listing 14-16`:

    using Microsoft.AspNetCore.Authentication;
    using System.Security.Claims;

    namespace ExampleApp.Custom {
        public class AuthHandler : IAuthenticationHandler {
            private HttpContext? context;
            private AuthenticationScheme? scheme;

            public Task InitializeAsync(AuthenticationScheme authScheme,
                    HttpContext httpContext) {
                context = httpContext;
                scheme = authScheme;
                return Task.CompletedTask;
            }

            public Task<AuthenticateResult> AuthenticateAsync() {
                AuthenticateResult result;
                string? user = context?.Request.Cookies["authUser"];
                if (user != null && scheme != null) {
                    Claim claim = new Claim(ClaimTypes.Name, user);
                    ClaimsIdentity ident = new ClaimsIdentity(scheme.Name);
                    ident.AddClaim(claim);
                    result = AuthenticateResult.Success(new AuthenticationTicket(new ClaimsPrincipal(ident), scheme.Name));
                } else {
                    result = AuthenticateResult.NoResult();
                }
                return Task.FromResult(result);
            }

            public Task ChallengeAsync(AuthenticationProperties? properties) {
                if (context != null) {
                    context.Response.StatusCode = StatusCodes.Status401Unauthorized;
                }
                return Task.CompletedTask;
            }

            public Task ForbidAsync(AuthenticationProperties? properties) {
                if (context != null) {
                    context.Response.StatusCode = StatusCodes.Status403Forbidden;
                }
                return Task.CompletedTask;
            }
        }
    }


***

Ignore `Listing 14-17` and configure the application using the following code in the `Program.cs` file:

    using ExampleApp;
    using ExampleApp.Custom;

    var builder = WebApplication.CreateBuilder(args);

    builder.Services.AddAuthentication(opts => {
        opts.AddScheme<AuthHandler>("qsv", "QueryStringValue");
        opts.DefaultScheme = "qsv";
    });
    builder.Services.AddAuthorization();


    var app = builder.Build();

    //app.UseMiddleware<CustomAuthentication>();
    app.UseAuthentication();

    app.UseMiddleware<RoleMemberships>();
    app.UseMiddleware<ClaimsReporter>();
    //app.UseMiddleware<CustomAuthorization>();
    app.UseAuthorization();

    app.MapGet("/", async context => {
        await context.Response.WriteAsync("Hello World!");
    });
    app.MapGet("/secret", SecretEndpoint.Endpoint)
        .WithDisplayName("secret");
    app.Map("/signin", CustomSignInAndSignOut.SignIn);
    app.Map("/signout", CustomSignInAndSignOut.SignOut);

    app.Run();


***

Use the following code for `Listing 14-18`:

    using Microsoft.AspNetCore.Authentication;
    using System.Security.Claims;

    namespace ExampleApp.Custom {
        public class AuthHandler : IAuthenticationSignInHandler {
            private HttpContext? context;
            private AuthenticationScheme? scheme;

            public Task InitializeAsync(AuthenticationScheme authScheme,
                    HttpContext httpContext) {
                context = httpContext;
                scheme = authScheme;
                return Task.CompletedTask;
            }

            public Task<AuthenticateResult> AuthenticateAsync() {
                AuthenticateResult result;
                string? user = context?.Request.Cookies["authUser"];
                if (user != null && scheme != null) {
                    Claim claim = new Claim(ClaimTypes.Name, user);
                    ClaimsIdentity ident = new ClaimsIdentity(scheme.Name);
                    ident.AddClaim(claim);
                    result = AuthenticateResult.Success(new AuthenticationTicket(new ClaimsPrincipal(ident), scheme.Name));
                } else {
                    result = AuthenticateResult.NoResult();
                }
                return Task.FromResult(result);
            }

            public Task ChallengeAsync(AuthenticationProperties? properties) {
                if (context != null) {
                    context.Response.StatusCode = StatusCodes.Status401Unauthorized;
                }
                return Task.CompletedTask;
            }

            public Task ForbidAsync(AuthenticationProperties? properties) {
                if (context != null) {
                    context.Response.StatusCode = StatusCodes.Status403Forbidden;
                }
                return Task.CompletedTask;
            }

            public Task SignInAsync(ClaimsPrincipal user,
                    AuthenticationProperties? properties) {
                if (context != null && user.Identity?.Name != null) {
                    context.Response.Cookies.Append("authUser", user.Identity.Name);
                }
                return Task.CompletedTask;
            }

            public Task SignOutAsync(AuthenticationProperties? properties) {
                if (context != null) {
                    context.Response.Cookies.Delete("authUser");
                }
                return Task.CompletedTask;
            }

        }
    }

***

Use the following code for `Listing 14-21`:

    using Microsoft.AspNetCore.Authentication;
    using Microsoft.AspNetCore.Mvc;
    using Microsoft.AspNetCore.Mvc.RazorPages;
    using Microsoft.AspNetCore.Mvc.Rendering;
    using System.Security.Claims;

    namespace ExampleApp.Pages {
        public class SignInModel : PageModel {

            public SelectList Users => new SelectList(UsersAndClaims.Users,
                User.Identity?.Name);

            public string Username { get; set; } = String.Empty;

            public int? Code { get; set; }

            public void OnGet(int? code) {
                Code = code;
                Username = User.Identity?.Name ?? "(No Signed In User)";
            }

            public async Task<ActionResult> OnPost(string username) {
                Claim claim = new Claim(ClaimTypes.Name, username);
                ClaimsIdentity ident = new ClaimsIdentity("simpleform");
                ident.AddClaim(claim);
                await HttpContext.SignInAsync(new ClaimsPrincipal(ident));
                return Redirect("/signin");
            }
        }
    }

***

Use the following code for `Listing 14-23`:

    using Microsoft.AspNetCore.Authentication;
    using Microsoft.AspNetCore.Mvc;
    using Microsoft.AspNetCore.Mvc.RazorPages;

    namespace ExampleApp.Pages {
        public class SignOutModel : PageModel {
            public string Username { get; set; } = String.Empty;

            public void OnGet() {
                Username = User.Identity?.Name ?? "(No Signed In User)";
            }

            public async Task<ActionResult> OnPost() {
                await HttpContext.SignOutAsync();
                return RedirectToPage("SignIn");
            }
        }
    }

***

Use the following code for `Listing 14-24`:

    using Microsoft.AspNetCore.Authentication;
    using System.Security.Claims;

    namespace ExampleApp.Custom {
        public class AuthHandler : IAuthenticationSignInHandler {
            private HttpContext? context;
            private AuthenticationScheme? scheme;

            public Task InitializeAsync(AuthenticationScheme authScheme,
                    HttpContext httpContext) {
                context = httpContext;
                scheme = authScheme;
                return Task.CompletedTask;
            }

            public Task<AuthenticateResult> AuthenticateAsync() {
                AuthenticateResult result;
                string? user = context?.Request.Cookies["authUser"];
                if (user != null && scheme != null) {
                    Claim claim = new Claim(ClaimTypes.Name, user);
                    ClaimsIdentity ident = new ClaimsIdentity(scheme.Name);
                    ident.AddClaim(claim);
                    result = AuthenticateResult.Success(new AuthenticationTicket(new ClaimsPrincipal(ident), scheme.Name));
                } else {
                    result = AuthenticateResult.NoResult();
                }
                return Task.FromResult(result);
            }

            public Task ChallengeAsync(AuthenticationProperties? properties) {
                if (context != null) {
                    //context.Response.StatusCode = StatusCodes.Status401Unauthorized;
                    context.Response.Redirect("/signin/401");
                }
                return Task.CompletedTask;
            }

            public Task ForbidAsync(AuthenticationProperties? properties) {
                if (context != null) {
                    //context.Response.StatusCode = StatusCodes.Status403Forbidden;
                    context.Response.Redirect("/signin/403");
                }
                return Task.CompletedTask;
            }

            public Task SignInAsync(ClaimsPrincipal user,
                    AuthenticationProperties? properties) {
                if (context != null && user.Identity?.Name != null) {
                    context.Response.Cookies.Append("authUser", user.Identity.Name);
                }
                return Task.CompletedTask;
            }

            public Task SignOutAsync(AuthenticationProperties? properties) {
                if (context != null) {
                    context.Response.Cookies.Delete("authUser");
                }
                return Task.CompletedTask;
            }

        }
    }

***

Ignore `Listing 14-25` and configure the application using the following code in the `Program.cs` file:


    using ExampleApp;
    using ExampleApp.Custom;

    var builder = WebApplication.CreateBuilder(args);

    builder.Services.AddAuthentication(opts => {
        opts.AddScheme<AuthHandler>("qsv", "QueryStringValue");
        opts.DefaultScheme = "qsv";
    });
    builder.Services.AddAuthorization();
    builder.Services.AddRazorPages();

    var app = builder.Build();

    app.UseStaticFiles();

    app.UseAuthentication();

    app.UseMiddleware<RoleMemberships>();
    app.UseMiddleware<ClaimsReporter>();

    app.UseAuthorization();

    app.MapGet("/", async context => {
        await context.Response.WriteAsync("Hello World!");
    });
    app.MapGet("/secret", SecretEndpoint.Endpoint)
        .WithDisplayName("secret");
    //app.Map("/signin", CustomSignInAndSignOut.SignIn);
    //app.Map("/signout", CustomSignInAndSignOut.SignOut);
    app.MapRazorPages();

    app.Run();


***

Ignore `Listing 14-26` and configure the application using the following code in the `Program.cs` file:

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

    var app = builder.Build();

    app.UseStaticFiles();

    app.UseAuthentication();

    app.UseMiddleware<RoleMemberships>();
    app.UseMiddleware<ClaimsReporter>();

    app.UseAuthorization();

    app.MapGet("/", async context => {
        await context.Response.WriteAsync("Hello World!");
    });
    app.MapGet("/secret", SecretEndpoint.Endpoint)
        .WithDisplayName("secret");
    app.MapRazorPages();

    app.Run();

***

Use the following code for `Listing 14-27`:

    using Microsoft.AspNetCore.Authentication;
    using Microsoft.AspNetCore.Mvc;
    using Microsoft.AspNetCore.Mvc.RazorPages;
    using Microsoft.AspNetCore.Mvc.Rendering;
    using System.Security.Claims;

    namespace ExampleApp.Pages {
        public class SignInModel : PageModel {

            public SelectList Users => new SelectList(UsersAndClaims.Users,
                User.Identity?.Name);

            public string Username { get; set; } = String.Empty;

            public int? Code { get; set; }

            public void OnGet(int? code) {
                Code = code;
                Username = User.Identity?.Name ?? "(No Signed In User)";
            }

            public async Task<ActionResult> OnPost(string username,
                    [FromQuery] string returnUrl) {

                Claim claim = new Claim(ClaimTypes.Name, username);
                ClaimsIdentity ident = new ClaimsIdentity("simpleform");
                ident.AddClaim(claim);
                await HttpContext.SignInAsync(new ClaimsPrincipal(ident));
                return Redirect(returnUrl ?? "/signin");
            }
        }
    }

***