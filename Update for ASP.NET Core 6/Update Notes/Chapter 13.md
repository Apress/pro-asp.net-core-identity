# Changes for Chapter 13

## The changes required in this chapter are the introduction of the minimal API for configuring ASP.NET Core applications.
***

Use the following commands for `Listing 13-1`:

    dotnet new globaljson --sdk-version 6.0.100 --output ExampleApp
    dotnet new web --no-https --output ExampleApp --framework net6.0
    dotnet new sln -o ExampleApp
    dotnet sln ExampleApp add ExampleApp

***


Ignore `Listing 13-12` and configure the application using the following code in the `Program.cs` file:

    var builder = WebApplication.CreateBuilder(args);

    builder.Services.AddRazorPages();
    builder.Services.AddControllersWithViews();

    var app = builder.Build();

    app.UseStaticFiles();

    app.MapGet("/", () => "Hello World!");
    app.MapRazorPages();
    app.MapDefaultControllerRoute();

    app.Run();

***