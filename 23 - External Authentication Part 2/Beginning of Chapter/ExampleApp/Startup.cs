using Microsoft.AspNetCore.Builder;
using Microsoft.AspNetCore.Hosting;
using Microsoft.AspNetCore.Http;
using Microsoft.Extensions.DependencyInjection;
using ExampleApp.Custom;
using Microsoft.AspNetCore.Authentication.Cookies;
using Microsoft.AspNetCore.Authorization;
using Microsoft.AspNetCore.Identity;
using ExampleApp.Identity;
using ExampleApp.Identity.Store;
using ExampleApp.Services;

namespace ExampleApp {
    public class Startup {

        public void ConfigureServices(IServiceCollection services) {
            services.AddSingleton<ILookupNormalizer, Normalizer>();
            services.AddSingleton<IUserStore<AppUser>, UserStore>();
            services.AddSingleton<IEmailSender, ConsoleEmailSender>();
            services.AddSingleton<ISMSSender, ConsoleSMSSender>();
            //services.AddSingleton<IUserClaimsPrincipalFactory<AppUser>,
            //    AppUserClaimsPrincipalFactory>();
            services.AddSingleton<IPasswordHasher<AppUser>, SimplePasswordHasher>();
            services.AddSingleton<IRoleStore<AppRole>, RoleStore>();
            //services.AddSingleton<IUserConfirmation<AppUser>, UserConfirmation>();

            services.AddOptions<ExternalAuthOptions>();

            services.AddIdentityCore<AppUser>(opts => {
                opts.Tokens.EmailConfirmationTokenProvider = "SimpleEmail";
                opts.Tokens.ChangeEmailTokenProvider = "SimpleEmail";
                opts.Tokens.PasswordResetTokenProvider =
                    TokenOptions.DefaultPhoneProvider;

                opts.Password.RequireNonAlphanumeric = false;
                opts.Password.RequireLowercase = false;
                opts.Password.RequireUppercase = false;
                opts.Password.RequireDigit = false;
                opts.Password.RequiredLength = 8;
                opts.Lockout.MaxFailedAccessAttempts = 3;
                opts.SignIn.RequireConfirmedAccount = true;
            })
            .AddTokenProvider<EmailConfirmationTokenGenerator>("SimpleEmail")
            .AddTokenProvider<PhoneConfirmationTokenGenerator>
                (TokenOptions.DefaultPhoneProvider)
            .AddTokenProvider<TwoFactorSignInTokenGenerator>
                (IdentityConstants.TwoFactorUserIdScheme)
            .AddTokenProvider<AuthenticatorTokenProvider<AppUser>>
                (TokenOptions.DefaultAuthenticatorProvider)
            .AddSignInManager()
            .AddRoles<AppRole>();

            //services.AddSingleton<IUserValidator<AppUser>, EmailValidator>();
            services.AddSingleton<IPasswordValidator<AppUser>, PasswordValidator>();
            services.AddScoped<IUserClaimsPrincipalFactory<AppUser>,
                AppUserClaimsPrincipalFactory>();
            services.AddSingleton<IRoleValidator<AppRole>, RoleValidator>();

            services.AddAuthentication(opts => {
                opts.DefaultScheme = IdentityConstants.ApplicationScheme;
                opts.AddScheme<ExternalAuthHandler>("demoAuth", "Demo Service");
            }).AddCookie(IdentityConstants.ApplicationScheme, opts => {
                opts.LoginPath = "/signin";
                opts.AccessDeniedPath = "/signin/403";
            })
            .AddCookie(IdentityConstants.TwoFactorUserIdScheme)
            .AddCookie(IdentityConstants.TwoFactorRememberMeScheme)
            .AddCookie(IdentityConstants.ExternalScheme);

            services.AddAuthorization(opts => {
                AuthorizationPolicies.AddPolicies(opts);
                opts.AddPolicy("Full2FARequired", builder => {
                    builder.RequireClaim("amr", "mfa");
                });
            });
            services.AddRazorPages();
            services.AddControllersWithViews();
        }

        public void Configure(IApplicationBuilder app, IWebHostEnvironment env) {

            app.UseStaticFiles();
            app.UseAuthentication();
            app.UseRouting();
            app.UseAuthorization();

            app.UseEndpoints(endpoints => {
                endpoints.MapRazorPages();
                endpoints.MapDefaultControllerRoute();
                endpoints.MapFallbackToPage("/Secret");
            });
        }
    }
}
