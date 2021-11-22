# Changes for Chapter 16

## Not all of the Identity API methods have  been correctly annotated for null state analysis, which requires the use of the #pragma directive in some listings. 
***

Ignore `Listing 16-1` and configure the application using the following code in the `Program.cs` file:

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

***

Use the following code for `Listing 16-2`:

    using Microsoft.AspNetCore.Authorization;
    using Microsoft.AspNetCore.Authorization.Infrastructure;

    namespace ExampleApp.Custom {

        public static class AuthorizationPolicies {

            public static void AddPolicies(AuthorizationOptions opts) {

                opts.AddPolicy("UsersExceptBob", builder =>
                        builder.RequireRole("User")
                    .AddRequirements(new AssertionRequirement(context =>
                        !string.Equals(context.User.Identity?.Name, "Bob"))));
                
                opts.AddPolicy("NotAdmins", builder =>
                    builder.AddRequirements(new AssertionRequirement(context =>
                        !context.User.IsInRole("Administrator"))));
            }
        }
    }

***

Use the following command for `Listing 16-6`:

    dotnet add package Microsoft.Extensions.Identity.Core --version 6.0.0 

***

Use the following code for `Listing 16-7`:

    namespace ExampleApp.Identity {
        public class AppUser {

            public string Id { get; set; } = Guid.NewGuid().ToString();

            public string UserName { get; set; } = String.Empty;

            public string NormalizedUserName { get; set; } = String.Empty;
        }
    }

***

Use the following code for `Listing 16-8`:

    using System.Collections;

    namespace ExampleApp.Identity {

        public static class StoreClassExtentions {

            public static T UpdateFrom<T>(this T target, T source) {
                UpdateFrom(target, source, out bool discardValue);
                return target;
            }

            public static T UpdateFrom<T>(this T target, T source, out bool changes) {
                object? value;
                int changeCount = 0;
                Type classType = typeof(T);
                foreach (var prop in classType.GetProperties()) {
                    if (prop.PropertyType.IsGenericType &&
                        prop.PropertyType.GetGenericTypeDefinition()
                            .Equals(typeof(IList<>))) {
                        Type listType = typeof(List<>).MakeGenericType(prop.PropertyType
                            .GetGenericArguments()[0]);
                        IList? sourceList = prop.GetValue(source) as IList;
                        if (sourceList != null) {
                            prop.SetValue(target, Activator.CreateInstance(listType,
                                sourceList));
                        }
                    } else {
                        if ((value = prop.GetValue(source)) != null
                                && !value.Equals(prop.GetValue(target))) {
                            classType.GetProperty(prop.Name)?.SetValue(target, value);
                            changeCount++;
                        }
                    }
                }
                changes = changeCount > 0;
                return target;
            }

            public static T Clone<T>(this T original) =>
                Activator.CreateInstance<T>().UpdateFrom(original);
        }
    }

***

Use the following code for `Listing 16-9`:

    using Microsoft.AspNetCore.Identity;
    using System.Collections.Concurrent;
    using System.Threading;
    using System.Threading.Tasks;

    namespace ExampleApp.Identity.Store {

        public partial class UserStore : IUserStore<AppUser> {
            private ConcurrentDictionary<string, AppUser> users
                = new ConcurrentDictionary<string, AppUser>();

            public Task<IdentityResult> CreateAsync(AppUser user,
                    CancellationToken token) {
                if (!users.ContainsKey(user.Id) && users.TryAdd(user.Id, user)) {
                    return Task.FromResult(IdentityResult.Success);
                }
                return Task.FromResult(Error);
            }

            public Task<IdentityResult> DeleteAsync(AppUser user, 
                    CancellationToken token) {
                AppUser? outUser;
                if (users.ContainsKey(user.Id) && users.TryRemove(user.Id, out outUser)) {
                    return Task.FromResult(IdentityResult.Success);
                }
                return Task.FromResult(Error);
            }

            public Task<IdentityResult> UpdateAsync(AppUser user,
                    CancellationToken token) {
                if (users.ContainsKey(user.Id)) {
                    users[user.Id].UpdateFrom(user);
                    return Task.FromResult(IdentityResult.Success);
                }
                return Task.FromResult(Error);
            }

            public void Dispose() {
                // do nothing
            }

            private IdentityResult Error => IdentityResult.Failed(new IdentityError {
                Code = "StorageFailure",
                Description = "User Store Error"
            });
        }
    }

***

Use the following code for `Listing 16-10`. Note the use of the #pragma directive to suppress null warnings.

    using System.Linq;
    using System.Threading;
    using System.Threading.Tasks;

    #pragma warning disable CS8619

    namespace ExampleApp.Identity.Store {

        public partial class UserStore {

            public Task<AppUser> FindByIdAsync(string userId, CancellationToken token) {
                return Task.FromResult(users.ContainsKey(userId) ? users[userId].Clone() : null);
            }

            public Task<AppUser> FindByNameAsync(string normalizedUserName,
                    CancellationToken token) =>
                Task.FromResult(users.Values.FirstOrDefault(user =>
                    user.NormalizedUserName == normalizedUserName)?.Clone());
        }
    }

***

Ignore `Listing 16-14` and configure the application using the following code in the `Program.cs` file:

    using ExampleApp.Custom;
    using Microsoft.AspNetCore.Authentication.Cookies;
    using Microsoft.AspNetCore.Authorization;
    using Microsoft.AspNetCore.Identity;
    using ExampleApp.Identity;
    using ExampleApp.Identity.Store;

    var builder = WebApplication.CreateBuilder(args);

    //builder.Services.AddTransient<IAuthorizationHandler,
    //    CustomRequirementHandler>();

    builder.Services.AddSingleton<ILookupNormalizer, Normalizer>();
    builder.Services.AddSingleton<IUserStore<AppUser>, UserStore>();
    builder.Services.AddIdentityCore<AppUser>();


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

***

Use the following code for `Listing 16-20`:

    using ExampleApp.Identity;
    using Microsoft.AspNetCore.Identity;
    using Microsoft.AspNetCore.Mvc;
    using Microsoft.AspNetCore.Mvc.RazorPages;
    using System.Threading.Tasks;

    namespace ExampleApp.Pages.Store {

        public class UsersModel : PageModel {

            public UsersModel(UserManager<AppUser> userMgr) => UserManager = userMgr;

            public UserManager<AppUser> UserManager { get; set; }

            public AppUser AppUserObject { get; set; } = new AppUser();

            public async Task OnGetAsync(string? id) {
                if (id != null) {
                    AppUserObject = await UserManager.FindByIdAsync(id) ?? new AppUser();
                }
            }

            public async Task<IActionResult> OnPost(AppUser user) {
                IdentityResult result;
                AppUser storeUser = await UserManager.FindByIdAsync(user.Id);
                if (storeUser == null) {
                    result = await UserManager.CreateAsync(user);
                } else {
                    storeUser.UpdateFrom(user);
                    result = await UserManager.UpdateAsync(storeUser);
                }
                if (result.Succeeded) {
                    return RedirectToPage("users", new { searchname = user.Id });
                } else {
                    foreach (IdentityError err in result.Errors) {
                        ModelState.AddModelError("", err.Description ?? "Error");
                    }
                    AppUserObject = user;
                    return Page();
                }
            }
        }
    }

***

Use the following code for `Listing 16-21`:

    @model AppUser
    <tr>
        <td>ID</td>
        <td>@Model?.Id</td>
    </tr>
    <tr>
        <td>Username</td>
        <td>
            <input class="w-00" asp-for="UserName" />
        </td>
    </tr>
    <tr>
        <td>Normalized UserName</td>
        <td>
            @(Model?.NormalizedUserName ?? "(Not Set)")
            <input type="hidden" asp-for="NormalizedUserName" />
        </td>
    </tr>

***

Use the following code for `Listing 16-24`:

    namespace ExampleApp.Identity {
        public class AppUser {

            public string Id { get; set; } = Guid.NewGuid().ToString();

            public string UserName { get; set; } = String.Empty;

            public string NormalizedUserName { get; set; } = String.Empty;


            public string EmailAddress { get; set; } = String.Empty;
            public string NormalizedEmailAddress { get; set; } = String.Empty;
            public bool EmailAddressConfirmed { get; set; }

            public string PhoneNumber { get; set; } = String.Empty;
            public bool PhoneNumberConfirmed { get; set; }

        }
    }

***

Use the following code for `Listing 16-25`. Note the use of the #pragma directive to suppress null warnings.

    using Microsoft.AspNetCore.Identity;

    #pragma warning disable CS8619

    namespace ExampleApp.Identity.Store {

        public partial class UserStore : IUserEmailStore<AppUser> {

            public Task<AppUser> FindByEmailAsync(string normalizedEmail,
                    CancellationToken token) =>
                Task.FromResult(Users.FirstOrDefault(user =>
                    user.NormalizedEmailAddress == normalizedEmail));

            public Task<string> GetEmailAsync(AppUser user,
                    CancellationToken token) =>
                Task.FromResult(user.EmailAddress);

            public Task SetEmailAsync(AppUser user, string email,
                    CancellationToken token) {
                user.EmailAddress = email;
                return Task.CompletedTask;
            }

            public Task<string> GetNormalizedEmailAsync(AppUser user,
                    CancellationToken token) =>
                Task.FromResult(user.NormalizedEmailAddress);

            public Task SetNormalizedEmailAsync(AppUser user, string normalizedEmail,
                    CancellationToken token) {
                user.NormalizedEmailAddress = normalizedEmail;
                return Task.CompletedTask;
            }

            public Task<bool> GetEmailConfirmedAsync(AppUser user,
                    CancellationToken token) =>
                Task.FromResult(user.EmailAddressConfirmed);

            public Task SetEmailConfirmedAsync(AppUser user, bool confirmed,
                    CancellationToken token) {
                user.EmailAddressConfirmed = confirmed;
                return Task.CompletedTask;
            }
        }
    }

***

Use the following code for `Listing 16-28`:

    @model AppUser
    @inject UserManager<AppUser> UserManager

    @if (UserManager.SupportsUserEmail) {
        <tr>
            <td>Email</td>
            <td>
                <input class="w-00" asp-for="EmailAddress" />
            </td>
        </tr>
        <tr>
            <td>Normalized Email</td>
            <td>
                @(Model?.NormalizedEmailAddress?? "(Not Set)")
                <input type="hidden" asp-for="NormalizedEmailAddress" />
                <input type="hidden" asp-for="EmailAddressConfirmed" />
            </td>
        </tr>
    }


***

Use the following code for `Listing 16-31`:

    namespace ExampleApp.Identity {
        public class AppUser {

            public string Id { get; set; } = Guid.NewGuid().ToString();

            public string UserName { get; set; } = String.Empty;

            public string NormalizedUserName { get; set; } = String.Empty;


            public string EmailAddress { get; set; } = String.Empty;
            public string NormalizedEmailAddress { get; set; } = String.Empty;
            public bool EmailAddressConfirmed { get; set; }

            public string PhoneNumber { get; set; } = String.Empty;
            public bool PhoneNumberConfirmed { get; set; }

            public string FavoriteFood { get; set; } = String.Empty;
            public string Hobby { get; set; } = String.Empty;

        }
    }

***

Ignore `Listing 16-36` and configure the application using the following code in the `Program.cs` file:

    using ExampleApp.Custom;
    using Microsoft.AspNetCore.Authentication.Cookies;
    using Microsoft.AspNetCore.Authorization;
    using Microsoft.AspNetCore.Identity;
    using ExampleApp.Identity;
    using ExampleApp.Identity.Store;

    var builder = WebApplication.CreateBuilder(args);

    builder.Services.AddSingleton<ILookupNormalizer, Normalizer>();
    builder.Services.AddSingleton<IUserStore<AppUser>, UserStore>();
    builder.Services.AddIdentityCore<AppUser>();
    builder.Services.AddSingleton<IUserValidator<AppUser>, EmailValidator>();

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

***