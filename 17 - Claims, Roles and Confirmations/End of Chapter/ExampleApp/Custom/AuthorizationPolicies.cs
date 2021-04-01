using Microsoft.AspNetCore.Authorization;
using System.Linq;
using Microsoft.AspNetCore.Authorization.Infrastructure;

namespace ExampleApp.Custom {

    public static class AuthorizationPolicies {

        public static void AddPolicies(AuthorizationOptions opts) {
            //opts.FallbackPolicy = new AuthorizationPolicy(
            //   new IAuthorizationRequirement[] {
            //       new RolesAuthorizationRequirement(
            //           new [] { "User", "Administrator" }),
            //       new AssertionRequirement(context =>
            //           !string.Equals(context.User.Identity.Name, "Bob"))
            //   }, new string[] { "TestScheme" });


            opts.AddPolicy("UsersExceptBob", builder =>
                    builder.RequireRole("User")
                .AddRequirements(new AssertionRequirement(context =>
                    !string.Equals(context.User.Identity.Name, "Bob"))));
            //.AddAuthenticationSchemes("OtherScheme"));

            opts.AddPolicy("NotAdmins", builder =>
                builder.AddRequirements(new AssertionRequirement(context =>
                    !context.User.IsInRole("Administrator"))));
        }
    }
}
