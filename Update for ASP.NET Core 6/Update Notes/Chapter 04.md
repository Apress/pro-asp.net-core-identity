# Changes for Chapter 4

## The changes required in this chapter are for null state analysis and the introduction of the minimal API for configuring ASP.NET Core applications.
***

Use the following commands for `Listing 4-3`:

    dotnet add package Microsoft.Extensions.Identity.Core --version 6.0.0 
    dotnet add package Microsoft.AspNetCore.Identity.EntityFrameworkCore --version 6.0.0

***

Use the following commands for `Listing 4-4`:

    dotnet add package Microsoft.AspNetCore.Identity.UI --version 6.0.0

***

Ignore `Listing 4-6` and configure the application using the following code in the `Program.cs` file:

    using Microsoft.EntityFrameworkCore;
    using IdentityApp.Models;
    using Microsoft.AspNetCore.Identity;
    using Microsoft.AspNetCore.Identity.EntityFrameworkCore;

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
    builder.Services.AddDefaultIdentity<IdentityUser>()
        .AddEntityFrameworkStores<IdentityDbContext>();


    var app = builder.Build();

    app.UseHttpsRedirection();
    app.UseStaticFiles();

    app.UseAuthentication();
    app.UseAuthorization();

    app.MapDefaultControllerRoute();
    app.MapRazorPages();

    app.Run();

***

Use the following content for `Listing 4-9`:

    <nav class="nav">
        @if (User.Identity?.IsAuthenticated == true) { 
            <a asp-area="Identity" asp-page="/Account/Manage/Index" 
                class="nav-link bg-secondary text-white">
                    @User.Identity?.Name
            </a>
            <a asp-area="Identity" asp-page="/Account/Logout" 
                class="nav-link bg-secondary text-white">
                    Logout
            </a>
        } else {
            <a asp-area="Identity" asp-page="/Account/Login" 
                    class="nav-link bg-secondary text-white">
                Login/Register
            </a>
        }
    </nav>

***

Ignore `Listing 4-14` and configure the application using the following code in the `Program.cs` file:

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
    builder.Services.AddDefaultIdentity<IdentityUser>()
        .AddEntityFrameworkStores<IdentityDbContext>();

    builder.Services.AddScoped<IEmailSender, ConsoleEmailSender>();

    var app = builder.Build();

    app.UseHttpsRedirection();
    app.UseStaticFiles();

    app.UseAuthentication();
    app.UseAuthorization();

    app.MapDefaultControllerRoute();
    app.MapRazorPages();

    app.Run();

***
