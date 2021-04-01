using Microsoft.AspNetCore.Builder;
using Microsoft.AspNetCore.Identity;
using Microsoft.Extensions.Configuration;
using Microsoft.Extensions.DependencyInjection;
using System.Threading.Tasks;

namespace IdentityApp {
    public static class DashBoardSeed {

        public static void SeedUserStoreForDashboard(this IApplicationBuilder app) {
            SeedStore(app).GetAwaiter().GetResult();
        }

        private async static Task SeedStore(IApplicationBuilder app) {
            using (var scope = app.ApplicationServices.CreateScope()) {
                IConfiguration config =
                    scope.ServiceProvider.GetService<IConfiguration>();
                UserManager<IdentityUser> userManager =
                    scope.ServiceProvider.GetService<UserManager<IdentityUser>>();
                RoleManager<IdentityRole> roleManager =
                    scope.ServiceProvider.GetService<RoleManager<IdentityRole>>();

                string roleName = config["Dashboard:Role"] ?? "Dashboard";
                string userName = config["Dashboard:User"] ?? "admin@example.com";
                string password = config["Dashboard:Password"] ?? "mysecret";

                if (!await roleManager.RoleExistsAsync(roleName)) {
                    await roleManager.CreateAsync(new IdentityRole(roleName));
                }
                IdentityUser dashboardUser =
                    await userManager.FindByEmailAsync(userName);
                if (dashboardUser == null) {
                    dashboardUser = new IdentityUser {
                        UserName = userName,
                        Email = userName,
                        EmailConfirmed = true
                    };
                    await userManager.CreateAsync(dashboardUser);
                    dashboardUser = await userManager.FindByEmailAsync(userName);
                    await userManager.AddPasswordAsync(dashboardUser, password);
                }
                if (!await userManager.IsInRoleAsync(dashboardUser, roleName)) {
                    await userManager.AddToRoleAsync(dashboardUser, roleName);
                }
            }
        }
    }
}
