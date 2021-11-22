# Changes for Chapter 3

## The changes required in this chapter are for null state analysis and the introduction of the minimal API for configuring ASP.NET Core applications.
***

Use the following commands for `Listing 3-1`:

    dotnet new globaljson --sdk-version 6.0.100 --output IdentityApp
    dotnet new web --no-https --output IdentityApp --framework net6.0
    dotnet new sln -o IdentityApp
    dotnet sln IdentityApp add IdentityApp

***

Use the following commands for `Listing 3-4`:

    dotnet add package Microsoft.EntityFrameworkCore.Design --version 6.0.0
    dotnet add package Microsoft.EntityFrameworkCore.SqlServer --version 6.0.0

***

Use the following commands for `Listing 3-5`:

    dotnet tool uninstall --global dotnet-ef
    dotnet tool install --global dotnet-ef --version 6.0.0

***

Use the following code for `Listing 3-7`:

    using System.ComponentModel.DataAnnotations.Schema;

    namespace IdentityApp.Models {

        public class Product {
            public long Id { get; set; }

            public string Name { get; set; } = String.Empty;

            [Column(TypeName = "decimal(8, 2)")]
            public decimal Price { get; set; }

            public string Category { get; set; } = String.Empty;
        }
    }

***

Use the following code for `Listing 3-8`:

    using Microsoft.EntityFrameworkCore;

    namespace IdentityApp.Models {
        public class ProductDbContext: DbContext {

            public ProductDbContext(DbContextOptions<ProductDbContext> options)
                : base(options) { }

            public DbSet<Product> Products => Set<Product>();

            protected override void OnModelCreating(ModelBuilder builder) {
                builder.Entity<Product>().HasData(
                    new Product { Id = 1, Name = "Kayak", 
                        Category = "Watersports", Price = 275 },
                    new Product { Id = 2, Name = "Lifejacket", 
                        Category = "Watersports", Price = 48.95m },
                    new Product { Id = 3, Name = "Soccer Ball",
                        Category = "Soccer", Price = 19.50m },
                    new Product { Id = 4, Name = "Corner Flags",
                        Category = "Soccer", Price = 34.95m },
                    new Product { Id = 5, Name = "Stadium",
                        Category = "Soccer", Price = 79500 },
                    new Product { Id = 6, Name = "Thinking Cap",
                        Category = "Chess", Price = 16 },
                    new Product { Id = 7, Name = "Unsteady Chair",
                        Category = "Chess", Price = 29.95m },
                    new Product { Id = 8, Name = "Human Chess Board",
                        Category = "Chess", Price = 75 },
                    new Product { Id = 9, Name = "Bling-Bling King",
                        Category = "Chess", Price = 1200});   
            }
        }
    }

***

Use the following code for `Listing 3-10`:

    @model IQueryable<Product>

    <h4 class="bg-primary text-white text-center p-2">MVC - Level 1 - Anyone</h4>

    <div class="text-center">
        <h6 class="p-2">
            The store contains @Model?.Count() products. 
        </h6>
    </div>

***

Use the following content for `Listing 3-12`:

    @model IQueryable<Product>

    <h4 class="bg-primary text-white text-center p-2">MVC - Level 2 - Signed In Users</h4>

    <div class="p-2">
        <table class="table table-sm table-striped table-bordered">
            <thead>
                <tr>
                    <th>ID</th><th>Name</th><th>Category</th>
                    <th class="text-right">Price</th>
                </tr>
            </thead>
            <tbody>
                @foreach (Product p in Model?.OrderBy(p => p.Id) ?? Enumerable.Empty<Product>()) {
                    <tr>
                        <td>@p.Id</td>
                        <td>@p.Name</td>
                        <td>@p.Category</td>
                        <td class="text-right">$@p.Price.ToString("F2")</td>
                    </tr>                
                }
            </tbody>
        </table>
    </div>

***

Use the following code for `Listing 3-13`:

    using IdentityApp.Models;
    using Microsoft.AspNetCore.Mvc;

    namespace IdentityApp.Controllers {

        public class AdminController : Controller {
            private ProductDbContext DbContext;

            public AdminController(ProductDbContext ctx) => DbContext = ctx;

            public IActionResult Index() => View(DbContext.Products);

            [HttpGet]
            public IActionResult Create() => View("Edit", new Product());

            [HttpGet]
            public IActionResult Edit(long id) {
                Product? p = DbContext.Find<Product>(id);
                if (p != null) {
                    return View("Edit", p);
                }
                return RedirectToAction(nameof(Index));
            }

            [HttpPost]
            public IActionResult Save(Product p) {
                DbContext.Update(p);
                DbContext.SaveChanges();
                return RedirectToAction(nameof(Index));
            }

            [HttpPost]
            public IActionResult Delete(long id) {
                Product? p = DbContext.Find<Product>(id);
                if (p != null) {
                    DbContext.Remove(p);
                    DbContext.SaveChanges();
                }
                return RedirectToAction(nameof(Index));
            }
        }
    }

***

Use the following content for `Listing 3-15`:

    @model IQueryable<Product>

    <h4 class="bg-primary text-white text-center p-2">MVC Level 3 - Administrators</h4>

    <div class="p-2">
        <table class="table table-sm table-striped table-bordered">
            <thead>
                <tr>
                    <th>ID</th><th>Name</th><th>Category</th>
                    <th class="text-right">Price</th><th></th>
                </tr>
            </thead>
            <tbody>
                @foreach (Product p in Model?.OrderBy(p => p.Id) ?? Enumerable.Empty<Product>()) {
                    <tr>
                        <td>@p.Id</td>
                        <td>@p.Name</td>
                        <td>@p.Category</td>
                        <td class="text-right">$@p.Price.ToString("F2")</td>
                        <td class="text-center">
                            <form method="post">
                                <a class="btn btn-sm btn-warning" asp-action="edit" 
                                    asp-route-id="@p.Id">Edit</a>
                                <button class="btn btn-sm btn-danger" 
                                    asp-action="delete" asp-route-id="@p.Id">
                                        Delete
                                </button>
                            </form>
                        </td>
                    </tr>                
                }
            </tbody>
        </table>
    </div>
    <a class="btn btn-primary mx-2" asp-action="Create">Create</a>

***

Ignore `Listing 3-31` and configure the application using the following code in the `Program.cs` file:

    using Microsoft.EntityFrameworkCore;
    using IdentityApp.Models;

    var builder = WebApplication.CreateBuilder(args);

    builder.Services.AddControllersWithViews();
    builder.Services.AddRazorPages();
    builder.Services.AddDbContext<ProductDbContext>(opts => {
        opts.UseSqlServer(
            builder.Configuration["ConnectionStrings:AppDataConnection"]);
    });

    var app = builder.Build();

    app.UseStaticFiles();
    app.MapDefaultControllerRoute();
    app.MapRazorPages();

    app.Run();

    ***

Ignore `Listing 3-37` and configure the application using the following code in the `Program.cs` file:

    using Microsoft.EntityFrameworkCore;
    using IdentityApp.Models;

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

    var app = builder.Build();

    app.UseHttpsRedirection();
    app.UseStaticFiles();
    app.MapDefaultControllerRoute();
    app.MapRazorPages();

    app.Run();

***

Use the following code for `Listing 3-40`:

    using IdentityApp.Models;
    using Microsoft.AspNetCore.Mvc;
    using Microsoft.AspNetCore.Authorization;

    namespace IdentityApp.Controllers {

        [Authorize(Roles = "Admin")]
        public class AdminController : Controller {
            private ProductDbContext DbContext;

            public AdminController(ProductDbContext ctx) => DbContext = ctx;

            public IActionResult Index() => View(DbContext.Products);

            [HttpGet]
            public IActionResult Create() => View("Edit", new Product());

            [HttpGet]
            public IActionResult Edit(long id) {
                Product? p = DbContext.Find<Product>(id);
                if (p != null) {
                    return View("Edit", p);
                }
                return RedirectToAction(nameof(Index));
            }

            [HttpPost]
            public IActionResult Save(Product p) {
                DbContext.Update(p);
                DbContext.SaveChanges();
                return RedirectToAction(nameof(Index));
            }

            [HttpPost]
            public IActionResult Delete(long id) {
                Product? p = DbContext.Find<Product>(id);
                if (p != null) {
                    DbContext.Remove(p);
                    DbContext.SaveChanges();
                }
                return RedirectToAction(nameof(Index));
            }
        }
    }

***

Use the following code for `Listing 3-41`:

    using IdentityApp.Models;
    using Microsoft.AspNetCore.Mvc;
    using Microsoft.AspNetCore.Mvc.RazorPages;
    using Microsoft.AspNetCore.Authorization;

    namespace IdentityApp.Pages {

        [Authorize(Roles = "Admin")]
        public class AdminModel : PageModel {

            public AdminModel(ProductDbContext ctx) => DbContext = ctx;

            public ProductDbContext DbContext { get; set; }

            public IActionResult OnPost(long id) {
                Product? p = DbContext.Find<Product>(id);
                if (p != null) {
                    DbContext.Remove(p);
                    DbContext.SaveChanges();
                }
                return Page();
            }
        }
    }

***

Use the following code for `Listing 3-42`:

    using IdentityApp.Models;
    using Microsoft.AspNetCore.Mvc;
    using Microsoft.AspNetCore.Mvc.RazorPages;
    using Microsoft.AspNetCore.Authorization;

    namespace IdentityApp.Pages {

        [Authorize(Roles = "Admin")]
        public class EditModel : PageModel {

            public EditModel(ProductDbContext ctx) => DbContext = ctx;

            public ProductDbContext DbContext { get; set; }
            public Product Product { get; set; } = new();

            public void OnGet(long id) {
                Product = DbContext.Find<Product>(id) ?? new Product();
            }

            public IActionResult OnPost([Bind(Prefix = "Product")] Product p) {
                DbContext.Update(p);
                DbContext.SaveChanges();
                return RedirectToPage("Admin");
            }
        }
    }

***

Use the following code for `Listing 3-43`:

    using Microsoft.EntityFrameworkCore;
    using IdentityApp.Models;

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

    var app = builder.Build();

    app.UseHttpsRedirection();
    app.UseStaticFiles();

    app.UseAuthentication();
    app.UseAuthorization();

    app.MapDefaultControllerRoute();
    app.MapRazorPages();

    app.Run();

***