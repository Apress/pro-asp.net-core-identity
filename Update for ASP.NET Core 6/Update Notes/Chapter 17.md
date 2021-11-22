# Changes for Chapter 17

## Not all of the Identity API methods have  been correctly annotated for null state analysis, which requires the use of the #pragma directive in some listings. 

***

Use the following code for `Listing 17-2`:

    using System.Security.Claims;

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

            public IList<Claim> Claims { get; set; } = new List<Claim>();
        }
    }

***

Use the following code for `Listing 17-3`:

    using Microsoft.AspNetCore.Identity;
    using System.Security.Claims;

    namespace ExampleApp.Identity.Store {
        public partial class UserStore : IUserClaimStore<AppUser>,
                IEqualityComparer<Claim> {

            public Task AddClaimsAsync(AppUser user, IEnumerable<Claim> claims,
                    CancellationToken token) {
                if (user.Claims == null) {
                    user.Claims = new List<Claim>();
                }
                foreach (Claim claim in claims) {
                    user.Claims.Add(claim);
                }
                return Task.CompletedTask;
            }

            public Task<IList<Claim>> GetClaimsAsync(AppUser user,
                    CancellationToken token) => Task.FromResult(user.Claims);

            public Task RemoveClaimsAsync(AppUser user, IEnumerable<Claim> claims,
                    CancellationToken token) {
                foreach (Claim c in user.Claims.Intersect(claims, this).ToList()) {
                    user.Claims.Remove(c);
                }
                return Task.CompletedTask;
            }

            public async Task ReplaceClaimAsync(AppUser user, Claim oldclaim,
                    Claim newClaim, CancellationToken token) {
                await RemoveClaimsAsync(user, new[] { oldclaim }, token);
                user.Claims.Add(newClaim);
            }

            public Task<IList<AppUser>> GetUsersForClaimAsync(Claim claim,
                    CancellationToken token) =>
                Task.FromResult(
                    Users.Where(u => u.Claims.Any(c => Equals(c, claim)))
                    .ToList() as IList<AppUser>);

            public bool Equals(Claim? first, Claim? second) =>
                first?.Type == second?.Type && string.Equals(first?.Value, second?.Value,
                        StringComparison.OrdinalIgnoreCase);

            public int GetHashCode(Claim claim) =>
                claim.Type.GetHashCode() + claim.Value.GetHashCode();
        }
    }

***

Use the following code for `Listing 17-4`:

    using Microsoft.AspNetCore.Identity;
    using System.Collections.Generic;
    using System.Linq;
    using System.Security.Claims;

    namespace ExampleApp.Identity.Store {

        public partial class UserStore {

            public ILookupNormalizer Normalizer { get; set; }

            public UserStore(ILookupNormalizer normalizer) {
                Normalizer = normalizer;
                SeedStore();
            }

            private void SeedStore() {

                var customData = new Dictionary<string, (string food, string hobby)> {
                    { "Alice", ("Pizza", "Running") },
                    { "Bob", ("Ice Cream", "Cinema") },
                    { "Charlie", ("Burgers", "Cooking") }
                };

                int idCounter = 0;

                string EmailFromName(string name) => $"{name.ToLower()}@example.com";

                foreach (string name in UsersAndClaims.Users) {
                    AppUser user = new AppUser {
                        Id = (++idCounter).ToString(),
                        UserName = name,
                        NormalizedUserName = Normalizer.NormalizeName(name),
                        EmailAddress = EmailFromName(name),
                        NormalizedEmailAddress =
                            Normalizer.NormalizeEmail(EmailFromName(name)),
                        EmailAddressConfirmed = true,
                        PhoneNumber = "123-4567",
                        PhoneNumberConfirmed = true,
                        FavoriteFood = customData[name].food,
                        Hobby = customData[name].hobby
                    };
                    user.Claims =  UsersAndClaims.UserData[user.UserName]
                        .Select(role => new Claim(ClaimTypes.Role, role)).ToList();
                    users.TryAdd(user.Id, user);
                }
            }
        }
    }

***

Use the following code for `Listing 17-11`:

    using ExampleApp.Identity;
    using Microsoft.AspNetCore.Identity;
    using Microsoft.AspNetCore.Mvc;
    using Microsoft.AspNetCore.Mvc.RazorPages;

    #pragma warning disable CS8603

    namespace ExampleApp.Pages.Store {

        public class UserRolesModel : PageModel {

            public UserRolesModel(UserManager<AppUser> userManager)
                => UserManager = userManager;

            public UserManager<AppUser> UserManager { get; set; }

            public IEnumerable<string> Roles { get; set; } = Enumerable.Empty<string>();

            [BindProperty(SupportsGet = true)]
            public string? Id { get; set; }

            public async void OnGet() {
                AppUser user = await GetUser();
                if (user != null) {
                    Roles = await UserManager.GetRolesAsync(user);
                }
            }

            public async Task<IActionResult> OnPostAdd(string newRole) {
                await UserManager.AddToRoleAsync(await GetUser(), newRole);
                return RedirectToPage();
            }

            public async Task<IActionResult> OnPostDelete(string role) {
                await UserManager.RemoveFromRoleAsync(await GetUser(), role);
                return RedirectToPage();
            }

            private Task<AppUser> GetUser() => Id == null
                ? null : UserManager.FindByIdAsync(Id);
        }
    }

***

Use the following code for `Listing 17-13`:

    using ExampleApp.Identity;
    using Microsoft.AspNetCore.Identity;
    using Microsoft.AspNetCore.Mvc;
    using Microsoft.AspNetCore.Mvc.RazorPages;
    using System.Security.Claims;

    #pragma warning disable CS8601
    #pragma warning disable CS8603

    namespace ExampleApp.Pages.Store {

        public class UserRolesModel : PageModel {

            public UserRolesModel(UserManager<AppUser> userManager)
                => UserManager = userManager;

            public UserManager<AppUser> UserManager { get; set; }

            public IEnumerable<string> Roles { get; set; } = Enumerable.Empty<string>();

            [BindProperty(SupportsGet = true)]
            public string? Id { get; set; }

            public async void OnGet() {
                AppUser user = await GetUser();
                if (user != null) {
                    //Roles = await UserManager.GetRolesAsync(user);
                    Roles = (await UserManager.GetClaimsAsync(user))?
                        .Where(c => c.Type == ClaimTypes.Role).Select(c => c.Value);

                }
            }

            public async Task<IActionResult> OnPostAdd(string newRole) {
                //await UserManager.AddToRoleAsync(await GetUser(), newRole);
                await UserManager.AddClaimAsync(await GetUser(),
                    new Claim(ClaimTypes.Role, newRole));
                return RedirectToPage();
            }

            public async Task<IActionResult> OnPostDelete(string role) {
                await UserManager.RemoveFromRoleAsync(await GetUser(), role);
                return RedirectToPage();
            }

            private Task<AppUser> GetUser() => Id == null
                ? null : UserManager.FindByIdAsync(Id);
        }
    }

***

Ignore `Listing 17-16` and configure the application using the following code in the `Program.cs` file:

    using ExampleApp.Custom;
    using Microsoft.AspNetCore.Authentication.Cookies;
    using Microsoft.AspNetCore.Authorization;
    using Microsoft.AspNetCore.Identity;
    using ExampleApp.Identity;
    using ExampleApp.Identity.Store;
    using ExampleApp.Services;

    var builder = WebApplication.CreateBuilder(args);

    builder.Services.AddSingleton<ILookupNormalizer, Normalizer>();
    builder.Services.AddSingleton<IUserStore<AppUser>, UserStore>();
    builder.Services.AddIdentityCore<AppUser>();
    builder.Services.AddSingleton<IUserValidator<AppUser>, EmailValidator>();
    builder.Services.AddSingleton<IEmailSender, ConsoleEmailSender>();
    builder.Services.AddSingleton<ISMSSender, ConsoleSMSSender>();


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

Use the following code for `Listing 17-17`:

    using System.Security.Claims;

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

            public IList<Claim> Claims { get; set; } = new List<Claim>();

            public string SecurityStamp { get; set; } = String.Empty;
        }
    }

***

Use the following code for `Listing 17-19`:

    @model AppUser
    @inject UserManager<AppUser> UserManager

    @if (UserManager.SupportsUserSecurityStamp) {
        <tr>
            <td>Security Stamp</td>
            <td>@Model?.SecurityStamp</td>
        </tr>
    }
    Add the element shown in Listing 17-20 to incorporate the new partial view into the application.
    Listing 17-20. Displaying the Security Stamp in the EditUser.cshtml File in the Pages/Store Folder
    @page "/users/edit/{id?}"
    @model ExampleApp.Pages.Store.UsersModel

    <div asp-validation-summary="All" class="text-danger m-2"></div>

    <div class="m-2">
        <form method="post">
            <input type="hidden" name="id" value="@Model.AppUserObject.Id" />    
            <table class="table table-sm table-striped">
                <tbody>
                    <partial name="_EditUserBasic" model="@Model.AppUserObject" />
                    <partial name="_EditUserEmail" model="@Model.AppUserObject" />
                    <partial name="_EditUserPhone" model="@Model.AppUserObject" />
                    <partial name="_EditUserCustom" model="@Model.AppUserObject" />
                    <partial name="_EditUserSecurityStamp" 
                        model="@Model.AppUserObject" />
                </tbody>
            </table>
            <div>
                <button type="submit" class="btn btn-primary">Save</button>
                <a asp-page="users" class="btn btn-secondary">Cancel</a>
            </div>
        </form>
    </div>

***

Ignore `Listing 17-24` and configure the application using the following code in the `Program.cs` file:

    using ExampleApp.Custom;
    using Microsoft.AspNetCore.Authentication.Cookies;
    using Microsoft.AspNetCore.Authorization;
    using Microsoft.AspNetCore.Identity;
    using ExampleApp.Identity;
    using ExampleApp.Identity.Store;
    using ExampleApp.Services;

    var builder = WebApplication.CreateBuilder(args);

    builder.Services.AddSingleton<ILookupNormalizer, Normalizer>();
    builder.Services.AddSingleton<IUserStore<AppUser>, UserStore>();
    builder.Services.AddIdentityCore<AppUser>();
    builder.Services.AddSingleton<IUserValidator<AppUser>, EmailValidator>();
    builder.Services.AddSingleton<IEmailSender, ConsoleEmailSender>();
    builder.Services.AddSingleton<ISMSSender, ConsoleSMSSender>();

    builder.Services.AddIdentityCore<AppUser>(opts => {
        opts.Tokens.EmailConfirmationTokenProvider = "SimpleEmail";
        opts.Tokens.ChangeEmailTokenProvider = "SimpleEmail";
    })
    .AddTokenProvider<EmailConfirmationTokenGenerator>("SimpleEmail")
    .AddTokenProvider<PhoneConfirmationTokenGenerator>(
        TokenOptions.DefaultPhoneProvider);


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

Use the following code for `Listing 17-26`:

    using ExampleApp.Identity;
    using ExampleApp.Services;
    using Microsoft.AspNetCore.Identity;
    using Microsoft.AspNetCore.Mvc;
    using Microsoft.AspNetCore.Mvc.RazorPages;

    namespace ExampleApp.Pages.Store {

        public class EmailPhoneChangeModel : PageModel {

            public EmailPhoneChangeModel(UserManager<AppUser> manager,
                    IEmailSender email, ISMSSender sms) {
                UserManager = manager;
                EmailSender = email;
                SMSSender = sms;
            }

            public UserManager<AppUser> UserManager { get; set; }
            public IEmailSender EmailSender { get; set; }
            public ISMSSender SMSSender { get; set; }

            [BindProperty(SupportsGet = true)]
            public string DataType { get; set; } = String.Empty;

            public bool IsEmail => DataType.Equals("email");

            public AppUser AppUser { get; set; } = new();

            public string LabelText => DataType ==
                "email" ? "Email Address" : "Phone Number";

            public string CurrentValue => IsEmail
                ? AppUser.EmailAddress : AppUser.PhoneNumber;

            public async Task OnGetAsync(string id, string data) {
                AppUser = await UserManager.FindByIdAsync(id);
            }

            public async Task<IActionResult> OnPost(string id, string dataValue) {
                AppUser = await UserManager.FindByIdAsync(id);
                if (IsEmail) {
                    string token = await UserManager
                        .GenerateChangeEmailTokenAsync(AppUser, dataValue);
                    EmailSender.SendMessage(AppUser, "Confirm Email",
                        "Please click the link to confirm your email address:",
                    $"http://localhost:5000/validate/{id}/email/{dataValue}:{token}");
                } else {
                    string token = await UserManager
                        .GenerateChangePhoneNumberTokenAsync(AppUser, dataValue);
                    SMSSender.SendMessage(AppUser,
                        $"Your confirmation token is {token}");
                }
                return RedirectToPage("EmailPhoneConfirmation",
                    new { id = id, dataType = DataType, dataValue = dataValue });
            }
        }
    }

***

Use the following code for `Listing 17-28`:

    using ExampleApp.Identity;
    using Microsoft.AspNetCore.Identity;
    using Microsoft.AspNetCore.Mvc;
    using Microsoft.AspNetCore.Mvc.RazorPages;

    namespace ExampleApp.Pages.Store {

        public class EmailPhoneConfirmationModel : PageModel {

            public EmailPhoneConfirmationModel(UserManager<AppUser> manager)
                => UserManager = manager;

            public UserManager<AppUser> UserManager { get; set; }

            [BindProperty(SupportsGet = true)]
            public string DataType { get; set; } = String.Empty;

            [BindProperty(SupportsGet = true)]
            public string DataValue { get; set; } = String.Empty;

            public bool IsEmail => DataType.Equals("email");

            public AppUser AppUser { get; set; } = new();

            public async Task<IActionResult> OnGetAsync(string id) {
                AppUser = await UserManager.FindByIdAsync(id);
                if (DataValue != null && DataValue.Contains(':')) {
                    string[] values = DataValue.Split(":");
                    return await Validate(values[0], values[1]);
                }
                return Page();
            }

            public async Task<IActionResult> OnPostAsync(string id,
                    string token, string dataValue) {
                AppUser = await UserManager.FindByIdAsync(id);
                return await Validate(dataValue, token);
            }

            private async Task<IActionResult> Validate(string value, string token) {
                IdentityResult result;
                if (IsEmail) {
                    result = await UserManager.ChangeEmailAsync(AppUser, value, token);
                } else {
                    result = await UserManager.ChangePhoneNumberAsync(AppUser, value,
                        token);
                }
                if (result.Succeeded) {
                    return Redirect($"/users/edit/{AppUser.Id}");
                } else {
                    foreach (IdentityError err in result.Errors) {
                        ModelState.AddModelError(string.Empty, err.Description);
                    }
                    return Page();
                }
            }
        }
    }

***

Use the following code for `Listing 17-29`:

    @model AppUser
    @inject UserManager<AppUser> UserManager

    @if (UserManager.SupportsUserEmail) {
        <tr>
            <td>Email</td>
            <td>
                @if (await UserManager.FindByIdAsync(Model?.Id) == null) {
                    <input class="w-00" asp-for="EmailAddress" />
                } else {
                    @Model?.EmailAddress
                    <input type="hidden" asp-for="EmailAddress" />
                    <a asp-page="EmailPhoneChange" asp-route-id="@Model?.Id" 
                    asp-route-datatype="email"
                    class="btn btn-sm btn-secondary align-top">Change</a>
                }
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

Use the following code for `Listing 17-30`:

    @model AppUser
    @inject UserManager<AppUser> UserManager

    @if (UserManager.SupportsUserPhoneNumber) {
        <tr>
            <td>Phone</td>
            <td>
                @if (await UserManager.FindByIdAsync(Model?.Id) == null) {
                    <input class="w-00" asp-for="PhoneNumber" />
                } else {
                    @Model?.PhoneNumber
                    <input type="hidden" asp-for="PhoneNumber" />
                    <a asp-page="EmailPhoneChange" asp-route-id="@Model?.Id" 
                    asp-route-datatype="phone"
                    class="btn btn-sm btn-secondary align-top">Change</a>
                }
                <input type="hidden" asp-for="PhoneNumberConfirmed" />
            </td>
        </tr>
    }

***