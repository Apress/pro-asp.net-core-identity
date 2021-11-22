# Changes for Chapter 2

## The changes required in this chapter are for null state analysis and the introduction of the minimal API for configuring ASP.NET Core applications.
***

Use the following commands for `Listing 2-4`:

    dotnet new globaljson --sdk-version 6.0.100 --output IdentityTodo
    dotnet new webapp --auth Individual --use-local-db true `
    --output IdentityTodo --framework net6.0
    dotnet new sln -o IdentityTodo
    dotnet sln IdentityTodo add IdentityTodo

***

Use the following code for `Listing 2-7`:

    namespace IdentityTodo.Data {

        public class TodoItem {

            public long Id { get; set; }

            public string? Task { get; set; }

            public bool Complete { get; set; }

            public string? Owner { get; set; }
        }
    }

***

Use the following code for `Listing 2-8`:

    using Microsoft.AspNetCore.Identity.EntityFrameworkCore;
    using Microsoft.EntityFrameworkCore;

    namespace IdentityTodo.Data;

    public class ApplicationDbContext : IdentityDbContext {
        public ApplicationDbContext(DbContextOptions<ApplicationDbContext> options)
            : base(options) {
        }

        public DbSet<TodoItem> TodoItems => Set<TodoItem>();
    }

***

Use the following commands for `Listing 2-9`:

    dotnet tool uninstall --global dotnet-ef
    dotnet tool install --global dotnet-ef --version 6.0.0

***

Ignore `Listing 2-12` and configure the application using the following code in the Program.cs file:

    using Microsoft.AspNetCore.Identity;
    using Microsoft.EntityFrameworkCore;
    using IdentityTodo.Data;

    var builder = WebApplication.CreateBuilder(args);

    // Add services to the container.
    var connectionString = builder.Configuration.GetConnectionString("DefaultConnection");
    builder.Services.AddDbContext<ApplicationDbContext>(options =>
        options.UseSqlServer(connectionString));
    builder.Services.AddDatabaseDeveloperPageExceptionFilter();

    builder.Services.AddDefaultIdentity<IdentityUser>(options => options.SignIn.RequireConfirmedAccount = false)
        .AddEntityFrameworkStores<ApplicationDbContext>();
    builder.Services.AddRazorPages();

    var app = builder.Build();

    if (app.Environment.IsDevelopment()) {
        app.UseMigrationsEndPoint();
    } else {
        app.UseExceptionHandler("/Error");
        app.UseHsts();
    }

    app.UseHttpsRedirection();
    app.UseStaticFiles();

    app.UseRouting();

    app.UseAuthentication();
    app.UseAuthorization();

    app.MapRazorPages();

app.Run();

***

Use the following content for `Listing 2-13`:

    @page
    @model IndexModel
    @{
        ViewData["Title"] = "To Do List";
    }

    <h2 class="text-center">To Do List</h2>
    <h4 class="text-center">(@User.Identity?.Name)</h4>

    <form method="post" asp-page-handler="ShowComplete" class="m-2">
        <div class="form-check">
            <input type="checkbox" class="form-check-input" asp-for="ShowComplete" 
                onchange="this.form.submit()"/>
            <label class="form-check-label">Show Completed Items</label>
        </div>
    </form>

    <table class="table table-sm table-striped table-bordered m-2">
        <thead><tr><th>Task</th><th/></tr></thead>
        <tbody>
            @if (Model.TodoItems.Count() == 0) {
                <tr>
                    <td colspan="2" class="text-center py-4">
                        You have done everything!
                    </td>
                </tr>
            } else {
                @foreach (TodoItem item in Model.TodoItems) {
                    <tr>
                        <td class="p-2">@item.Task</td>
                        <td class="text-center py-2">
                            <form method="post" asp-page-handler="MarkItem">
                                <input type="hidden" name="id" value="@item.Id" />
                                <input type="hidden" asp-for="ShowComplete" />
                                <button type="submit" class="btn btn-sm btn-secondary">
                                    @(item.Complete ? "Mark Not Done" : "Done")
                                </button>
                            </form>
                        </td>
                    </tr>
                }
            }
        </tbody>
        <tfoot>
            <tr>
                <td class="pt-4">
                    <form method="post" asp-page-handler="AddItem" id="addItem">
                        <input type="hidden" asp-for="ShowComplete" />
                        <input name="task" placeholder="Enter new to do" 
                            class="form-control" />
                    </form>
                </td>
                <td class="text-center pt-4">
                    <button type="submit" form="addItem" 
                            class="btn btn-sm btn-secondary">
                        Add
                    </button>
                </td>
            </tr>
        </tfoot>
    </table>

***

Use the following code for `Listing 2-14`:

    using IdentityTodo.Data;
    using Microsoft.AspNetCore.Authorization;
    using Microsoft.AspNetCore.Mvc;
    using Microsoft.AspNetCore.Mvc.RazorPages;

    namespace IdentityTodo.Pages {

        [Authorize]
        public class IndexModel : PageModel {
            private ApplicationDbContext Context;

            public IndexModel(ApplicationDbContext ctx) {
                Context = ctx;
            }

            [BindProperty(SupportsGet = true)]
            public bool ShowComplete { get; set; } = false;

            public IEnumerable<TodoItem> TodoItems { get; set; } 
                = Enumerable.Empty<TodoItem>();

            public void OnGet() {
                if (User.Identity?.Name != null) {
                    TodoItems = Context.TodoItems
                        .Where(t => t.Owner == User.Identity.Name).OrderBy(t => t.Task);
                    if (!ShowComplete) {
                        TodoItems = TodoItems.Where(t => !t.Complete);
                    }
                    TodoItems = TodoItems.ToList();
                }
            }

            public IActionResult OnPostShowComplete() {
                return RedirectToPage(new { ShowComplete });
            }

            public async Task<IActionResult> OnPostAddItemAsync(string task) {
                if (!string.IsNullOrEmpty(task)) {
                    TodoItem item = new TodoItem {
                        Task = task,
                        Owner = User.Identity?.Name ?? String.Empty,
                        Complete = false
                    };
                    await Context.AddAsync(item);
                    await Context.SaveChangesAsync();
                }
                return RedirectToPage(new { ShowComplete });
            }

            public async Task<IActionResult> OnPostMarkItemAsync(long id) {
                TodoItem? item = Context.TodoItems.Find(id);
                if (item != null) {
                    item.Complete = !item.Complete;
                    await Context.SaveChangesAsync();
                }
                return RedirectToPage(new { ShowComplete });
            }
        }
    }

***