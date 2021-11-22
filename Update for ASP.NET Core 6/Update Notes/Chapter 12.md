# Changes for Chapter 11

## The configuration of the cookie used to identify users has changed, which is reflected in the replacement code for Listing 12-15. This listing also reflects a correction reported for the original code, in which I did not correctly configure the cookie.
***

Use the following code for `Listing 12-1`:

    using IdentityApp.Models;
    using Microsoft.AspNetCore.Mvc;
    using System.ComponentModel.DataAnnotations;

    namespace IdentityApp.Controllers {

        [ApiController]
        [Route("/api/data")]
        public class ValuesController : ControllerBase {
            private ProductDbContext DbContext;

            public ValuesController(ProductDbContext dbContext) {
                DbContext = dbContext;
            }

            [HttpGet]
            public IEnumerable<Product> GetProducts() => DbContext.Products;

            [HttpPost]
            public async Task<IActionResult> CreateProduct([FromBody]
                    ProductBindingTarget target) {
                if (ModelState.IsValid) {
                    Product product = new Product {
                        Name = target.Name, Price = target.Price,
                        Category = target.Category
                    };
                    await DbContext.AddAsync(product);
                    await DbContext.SaveChangesAsync();
                    return Ok(product);
                }
                return BadRequest(ModelState);
            }

            [HttpDelete("{id}")]
            public Task DeleteProduct(long id) {
                DbContext.Products.Remove(new Product { Id = id });
                return DbContext.SaveChangesAsync();
            }
        }

        public class ProductBindingTarget {
            [Required]
            public string Name { get; set; } = String.Empty;

            [Required]
            public decimal Price { get; set; }

            [Required]
            public string Category { get; set; } = String.Empty;
        }
    }

***

Use the following code for `Listing 12-7`:

    using IdentityApp.Models;
    using Microsoft.AspNetCore.Mvc;
    using System.ComponentModel.DataAnnotations;
    using Microsoft.AspNetCore.Authorization;

    namespace IdentityApp.Controllers {

        [Authorize]
        [ApiController]
        [Route("/api/data")]
        public class ValuesController : ControllerBase {
            private ProductDbContext DbContext;

            public ValuesController(ProductDbContext dbContext) {
                DbContext = dbContext;
            }

            [HttpGet]
            public IEnumerable<Product> GetProducts() => DbContext.Products;

            [HttpPost]
            public async Task<IActionResult> CreateProduct([FromBody]
                    ProductBindingTarget target) {
                if (ModelState.IsValid) {
                    Product product = new Product {
                        Name = target.Name, Price = target.Price,
                        Category = target.Category
                    };
                    await DbContext.AddAsync(product);
                    await DbContext.SaveChangesAsync();
                    return Ok(product);
                }
                return BadRequest(ModelState);
            }

            [HttpDelete("{id}")]
            public Task DeleteProduct(long id) {
                DbContext.Products.Remove(new Product { Id = id });
                return DbContext.SaveChangesAsync();
            }
        }

        public class ProductBindingTarget {
            [Required]
            public string Name { get; set; } = String.Empty;

            [Required]
            public decimal Price { get; set; }

            [Required]
            public string Category { get; set; } = String.Empty;
        }
    }

***

Ignore `Listing 12-11` and configure the application using the following code in the `Program.cs` file:

    using Microsoft.EntityFrameworkCore;
    using IdentityApp.Models;
    using Microsoft.AspNetCore.Identity;
    using Microsoft.AspNetCore.Identity.EntityFrameworkCore;
    using Microsoft.AspNetCore.Identity.UI.Services;
    using IdentityApp.Services;
    using IdentityApp;

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

    builder.Services.AddIdentity<IdentityUser, IdentityRole>(opts => {
        opts.Password.RequiredLength = 8;
        opts.Password.RequireDigit = false;
        opts.Password.RequireLowercase = false;
        opts.Password.RequireUppercase = false;
        opts.Password.RequireNonAlphanumeric = false;
        opts.SignIn.RequireConfirmedAccount = true;
    }).AddEntityFrameworkStores<IdentityDbContext>()
        .AddDefaultTokenProviders();

    builder.Services.AddScoped<TokenUrlEncoderService>();
    builder.Services.AddScoped<IdentityEmailService>();

    builder.Services.AddScoped<IEmailSender, ConsoleEmailSender>();

    builder.Services.AddAuthentication()
        .AddFacebook(opts => {
            opts.AppId = builder. Configuration["Facebook:AppId"];
            opts.AppSecret = builder.Configuration["Facebook:AppSecret"];
        })
        .AddGoogle(opts => {
            opts.ClientId = builder.Configuration["Google:ClientId"];
            opts.ClientSecret = builder.Configuration["Google:ClientSecret"];
        })
        .AddTwitter(opts => {
            opts.ConsumerKey = builder.Configuration["Twitter:ApiKey"];
            opts.ConsumerSecret = builder.Configuration["Twitter:ApiSecret"];
            opts.RetrieveUserDetails = true;
        });

    builder.Services.ConfigureApplicationCookie(opts => {
        opts.LoginPath = "/Identity/SignIn";
        opts.LogoutPath = "/Identity/SignOut";
        opts.AccessDeniedPath = "/Identity/Forbidden";
        opts.Events.DisableRedirectionForApiClients();
    });

    builder.Services.Configure<SecurityStampValidatorOptions>(opts => {
        opts.ValidationInterval = System.TimeSpan.FromMinutes(1);
    });

    var app = builder.Build();

    app.UseHttpsRedirection();
    app.UseStaticFiles();

    app.UseAuthentication();
    app.UseAuthorization();

    app.MapDefaultControllerRoute();
    app.MapRazorPages();

    app.SeedUserStoreForDashboard();

    app.Run();

***

Use the following code for `Listing 12-14`:

    using Microsoft.AspNetCore.Identity;
    using Microsoft.AspNetCore.Mvc;
    using System.ComponentModel.DataAnnotations;
    using System.Threading.Tasks;
    using SignInResult = Microsoft.AspNetCore.Identity.SignInResult;

    namespace IdentityApp.Controllers {

        [ApiController]
        [Route("/api/auth")]
        public class ApiAuthController : ControllerBase {
            private SignInManager<IdentityUser> SignInManager;

            public ApiAuthController(SignInManager<IdentityUser> signMgr) {
                SignInManager = signMgr;
            }

            [HttpPost("signin")]
            public async Task<object> ApiSignIn(
                    [FromBody] SignInCredentials creds) {
                SignInResult result = await SignInManager.PasswordSignInAsync(
                    creds.Email, creds.Password, true, true);
                return new { success = result.Succeeded };
            }

            [HttpPost("signout")]
            public async Task<IActionResult> ApiSignOut() {
                await SignInManager.SignOutAsync();
                return Ok();
            }
        }

        public class SignInCredentials {
            [Required]
            public string? Email { get; set; }
            [Required]
            public string? Password { get; set; }
        }
    }

***

Ignore `Listing 11-15` and configure the application using the following code in the `Program.cs` file:

    using Microsoft.EntityFrameworkCore;
    using IdentityApp.Models;
    using Microsoft.AspNetCore.Identity;
    using Microsoft.AspNetCore.Identity.EntityFrameworkCore;
    using Microsoft.AspNetCore.Identity.UI.Services;
    using IdentityApp.Services;
    using IdentityApp;

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

    builder.Services.AddIdentity<IdentityUser, IdentityRole>(opts => {
        opts.Password.RequiredLength = 8;
        opts.Password.RequireDigit = false;
        opts.Password.RequireLowercase = false;
        opts.Password.RequireUppercase = false;
        opts.Password.RequireNonAlphanumeric = false;
        opts.SignIn.RequireConfirmedAccount = true;
    }).AddEntityFrameworkStores<IdentityDbContext>()
        .AddDefaultTokenProviders();

    builder.Services.AddScoped<TokenUrlEncoderService>();
    builder.Services.AddScoped<IdentityEmailService>();

    builder.Services.AddScoped<IEmailSender, ConsoleEmailSender>();

    builder.Services.AddAuthentication()
        .AddFacebook(opts => {
            opts.AppId = builder. Configuration["Facebook:AppId"];
            opts.AppSecret = builder.Configuration["Facebook:AppSecret"];
        })
        .AddGoogle(opts => {
            opts.ClientId = builder.Configuration["Google:ClientId"];
            opts.ClientSecret = builder.Configuration["Google:ClientSecret"];
        })
        .AddTwitter(opts => {
            opts.ConsumerKey = builder.Configuration["Twitter:ApiKey"];
            opts.ConsumerSecret = builder.Configuration["Twitter:ApiSecret"];
            opts.RetrieveUserDetails = true;
        });

    builder.Services.ConfigureApplicationCookie(opts => {
        opts.LoginPath = "/Identity/SignIn";
        opts.LogoutPath = "/Identity/SignOut";
        opts.AccessDeniedPath = "/Identity/Forbidden";
        opts.Events.DisableRedirectionForApiClients();
        opts.Cookie.HttpOnly = false;
        opts.Cookie.SameSite = SameSiteMode.None;
    });

    builder.Services.Configure<SecurityStampValidatorOptions>(opts => {
        opts.ValidationInterval = System.TimeSpan.FromMinutes(1);
    });

    builder.Services.AddCors(opts => {
        opts.AddDefaultPolicy(builder => {
            builder.WithOrigins("http://localhost:5100")
                .AllowAnyHeader()
                .AllowAnyMethod()
                .AllowCredentials();
        });
    });

    var app = builder.Build();

    app.UseHttpsRedirection();
    app.UseStaticFiles();

    app.UseCors();

    app.UseAuthentication();
    app.UseAuthorization();

    app.MapDefaultControllerRoute();
    app.MapRazorPages();

    app.SeedUserStoreForDashboard();

    app.Run();

***

Use the following command  for `Listing 12-21`:

    dotnet add package Microsoft.AspNetCore.Authentication.JwtBearer --version 6.0.0

***

Ignore `Listing 12-22` and configure the application using the following code in the `Program.cs` file:

    using Microsoft.EntityFrameworkCore;
    using IdentityApp.Models;
    using Microsoft.AspNetCore.Identity;
    using Microsoft.AspNetCore.Identity.EntityFrameworkCore;
    using Microsoft.AspNetCore.Identity.UI.Services;
    using IdentityApp.Services;
    using IdentityApp;
    using Microsoft.AspNetCore.Authentication.JwtBearer;
    using Microsoft.IdentityModel.Tokens;
    using System.Text;

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

    builder.Services.AddIdentity<IdentityUser, IdentityRole>(opts => {
        opts.Password.RequiredLength = 8;
        opts.Password.RequireDigit = false;
        opts.Password.RequireLowercase = false;
        opts.Password.RequireUppercase = false;
        opts.Password.RequireNonAlphanumeric = false;
        opts.SignIn.RequireConfirmedAccount = true;
    }).AddEntityFrameworkStores<IdentityDbContext>()
        .AddDefaultTokenProviders();

    builder.Services.AddScoped<TokenUrlEncoderService>();
    builder.Services.AddScoped<IdentityEmailService>();

    builder.Services.AddScoped<IEmailSender, ConsoleEmailSender>();

    builder.Services.AddAuthentication()
        .AddFacebook(opts => {
            opts.AppId = builder.Configuration["Facebook:AppId"];
            opts.AppSecret = builder.Configuration["Facebook:AppSecret"];
        })
        .AddGoogle(opts => {
            opts.ClientId = builder.Configuration["Google:ClientId"];
            opts.ClientSecret = builder.Configuration["Google:ClientSecret"];
        })
        .AddTwitter(opts => {
            opts.ConsumerKey = builder.Configuration["Twitter:ApiKey"];
            opts.ConsumerSecret = builder.Configuration["Twitter:ApiSecret"];
            opts.RetrieveUserDetails = true;
        })
        .AddJwtBearer(JwtBearerDefaults.AuthenticationScheme, opts => {
            opts.TokenValidationParameters.ValidateAudience = false;
            opts.TokenValidationParameters.ValidateIssuer = false;
            opts.TokenValidationParameters.IssuerSigningKey
                = new SymmetricSecurityKey(Encoding.UTF8.GetBytes(
                    builder.Configuration["BearerTokens:Key"]));
        });


    builder.Services.ConfigureApplicationCookie(opts => {
        opts.LoginPath = "/Identity/SignIn";
        opts.LogoutPath = "/Identity/SignOut";
        opts.AccessDeniedPath = "/Identity/Forbidden";
        opts.Events.DisableRedirectionForApiClients();
        opts.Cookie.HttpOnly = false;
        opts.Cookie.SameSite = SameSiteMode.None;
    });

    builder.Services.Configure<SecurityStampValidatorOptions>(opts => {
        opts.ValidationInterval = System.TimeSpan.FromMinutes(1);
    });

    builder.Services.AddCors(opts => {
        opts.AddDefaultPolicy(builder => {
            builder.WithOrigins("http://localhost:5100")
                .AllowAnyHeader()
                .AllowAnyMethod()
                .AllowCredentials();
        });
    });

    var app = builder.Build();

    app.UseHttpsRedirection();
    app.UseStaticFiles();

    app.UseCors();

    app.UseAuthentication();
    app.UseAuthorization();

    app.MapDefaultControllerRoute();
    app.MapRazorPages();

    app.SeedUserStoreForDashboard();

    app.Run();

***

Use the following code for `Listing 12-23`:

    using Microsoft.AspNetCore.Identity;
    using Microsoft.AspNetCore.Mvc;
    using System.ComponentModel.DataAnnotations;
    using System.Threading.Tasks;
    using SignInResult = Microsoft.AspNetCore.Identity.SignInResult;
    using Microsoft.Extensions.Configuration;
    using System.IdentityModel.Tokens.Jwt;
    using Microsoft.IdentityModel.Tokens;
    using System.Linq;
    using System;
    using System.Text;

    namespace IdentityApp.Controllers {

        [ApiController]
        [Route("/api/auth")]
        public class ApiAuthController : ControllerBase {
            private SignInManager<IdentityUser> SignInManager;
            private UserManager<IdentityUser> UserManager;
            private IConfiguration Configuration;

            public ApiAuthController(SignInManager<IdentityUser> signMgr,
                    UserManager<IdentityUser> usrMgr,
                    IConfiguration config) {
                SignInManager = signMgr;
                UserManager = usrMgr;
                Configuration = config;
            }

            [HttpPost("signin")]
            public async Task<object> ApiSignIn(
                    [FromBody] SignInCredentials creds) {
                IdentityUser user = await UserManager.FindByEmailAsync(creds.Email);
                SignInResult result = await SignInManager.CheckPasswordSignInAsync(user,
                    creds.Password, true);
                if (result.Succeeded) {
                    SecurityTokenDescriptor descriptor = new SecurityTokenDescriptor {
                        Subject = (await SignInManager.CreateUserPrincipalAsync(user))
                            .Identities.First(),
                        Expires = DateTime.Now.AddMinutes(int.Parse(
                            Configuration["BearerTokens:ExpiryMins"])),
                        SigningCredentials = new SigningCredentials(
                            new SymmetricSecurityKey(Encoding.UTF8.GetBytes(
                                Configuration["BearerTokens:Key"])),
                                SecurityAlgorithms.HmacSha256Signature)
                    };
                    JwtSecurityTokenHandler handler = new JwtSecurityTokenHandler();
                    SecurityToken secToken = new JwtSecurityTokenHandler()
                        .CreateToken(descriptor);
                    return new { success = true, token = handler.WriteToken(secToken) };
                }
                return new { success = false };
            }

            //[HttpPost("signout")]
            //public async Task<IActionResult> ApiSignOut() {
            //    await SignInManager.SignOutAsync();
            //    return Ok();
            //}
        }

        public class SignInCredentials {
            [Required]
            public string? Email { get; set; }
            [Required]
            public string? Password { get; set; }
        }
    }

***

Use the following code for `Listing 12-24`:

    using IdentityApp.Models;
    using Microsoft.AspNetCore.Mvc;
    using System.ComponentModel.DataAnnotations;
    using Microsoft.AspNetCore.Authorization;
    using Microsoft.AspNetCore.Authentication.JwtBearer;

    namespace IdentityApp.Controllers {

        [Authorize(AuthenticationSchemes = JwtBearerDefaults.AuthenticationScheme)]
        [ApiController]
        [Route("/api/data")]
        public class ValuesController : ControllerBase {
            private ProductDbContext DbContext;

            public ValuesController(ProductDbContext dbContext) {
                DbContext = dbContext;
            }

            [HttpGet]
            public IEnumerable<Product> GetProducts() => DbContext.Products;

            [HttpPost]
            public async Task<IActionResult> CreateProduct([FromBody]
                    ProductBindingTarget target) {
                if (ModelState.IsValid) {
                    Product product = new Product {
                        Name = target.Name, Price = target.Price,
                        Category = target.Category
                    };
                    await DbContext.AddAsync(product);
                    await DbContext.SaveChangesAsync();
                    return Ok(product);
                }
                return BadRequest(ModelState);
            }

            [HttpDelete("{id}")]
            public Task DeleteProduct(long id) {
                DbContext.Products.Remove(new Product { Id = id });
                return DbContext.SaveChangesAsync();
            }
        }

        public class ProductBindingTarget {
            [Required]
            public string Name { get; set; } = String.Empty;

            [Required]
            public decimal Price { get; set; }

            [Required]
            public string Category { get; set; } = String.Empty;
        }
    }

***