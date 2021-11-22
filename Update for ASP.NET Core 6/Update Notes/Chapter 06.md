# Changes for Chapter 6

## The `dotnet aspnet-codegenerator` command used to generate scaffolded content adds configuration statements to the `Program.cs` file every time it runs, even when Identity has already been configured. As noted in the changes below, you must remove this statement after each scaffold operation.

***

Use the following commands for `Listing 6-3`:

    dotnet tool uninstall --global dotnet-aspnet-codegenerator
    dotnet tool install --global dotnet-aspnet-codegenerator --version 6.0.0

***

Use the following command for `Listing 6-4`:

    dotnet add package Microsoft.VisualStudio.Web.CodeGeneration.Design --version 6.0.0

***

Use the following content for `Listing 6-8`:

    @model Microsoft.AspNetCore.Authentication.AuthenticationScheme

    <button type="submit" 
            class="btn btn-primary" name="provider" value="@Model?.Name">
        <i class="@($"fab fa-{Model?.Name.ToLower()}")"></i>
        @Model?.DisplayName
    </button>

***

Remove the following statements from the `Program.cs` file after running the command in `Listing 6-9`:

    var connectionString = builder.Configuration.GetConnectionString("IdentityDbContextConnection");
    builder.Services.AddDbContext<IdentityDbContext>(options => options.UseSqlServer(connectionString));

These statements are near the start of the `Program.cs` file.

***

Use the following content for `Listing 6-10`:

    ...
    <form id="external-account" asp-page="./ExternalLogin" asp-route-returnUrl="@Model.ReturnUrl" method="post" class="form-horizontal">
        <div>
            <p>
                @foreach (var provider in Model.ExternalLogins ?? Enumerable.Empty<Microsoft.AspNetCore.Authentication.AuthenticationScheme>()) {
                    <partial name="_ExternalButtonPartial" model="provider" />
                }                               
            </p>
        </div>
    </form>
    ...

***

Remove the following statements from the `Program.cs` file after running the command in `Listing 6-11`:

    var connectionString = builder.Configuration.GetConnectionString("IdentityDbContextConnection");
    builder.Services.AddDbContext<IdentityDbContext>(options => options.UseSqlServer(connectionString));

These statements are near the start of the `Program.cs` file.

***

Use the following content for `Listing 6-12`:

    ...
    <form id="external-account" asp-page="./ExternalLogin" asp-route-returnUrl="@Model.ReturnUrl" method="post" class="form-horizontal">
        <div>
            <p>
                @foreach (var provider in Model.ExternalLogins ?? Enumerable.Empty<Microsoft.AspNetCore.Authentication.AuthenticationScheme>())
                {
                    <partial name="_ExternalButtonPartial" model="provider" />
                }
            </p>
        </div>
    </form>
    ...

***

Remove the following statements from the `Program.cs` file after running the command in `Listing 6-15`:

    var connectionString = builder.Configuration.GetConnectionString("IdentityDbContextConnection");
    builder.Services.AddDbContext<IdentityDbContext>(options => options.UseSqlServer(connectionString));

These statements are near the start of the `Program.cs` file.

***

Remove the following statements from the `Program.cs` file after running the command in `Listing 6-23`:

    var connectionString = builder.Configuration.GetConnectionString("IdentityDbContextConnection");
    builder.Services.AddDbContext<IdentityDbContext>(options => options.UseSqlServer(connectionString));

These statements are near the start of the `Program.cs` file.

***

Remove the following statements from the `Program.cs` file after running the command in `Listing 6-28`:

    var connectionString = builder.Configuration.GetConnectionString("IdentityDbContextConnection");
    builder.Services.AddDbContext<IdentityDbContext>(options => options.UseSqlServer(connectionString));

These statements are near the start of the `Program.cs` file.

***