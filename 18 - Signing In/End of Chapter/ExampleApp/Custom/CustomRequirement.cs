using Microsoft.AspNetCore.Authorization;

namespace ExampleApp.Custom {

    public class CustomRequirement : IAuthorizationRequirement {

        public string Name { get; set; }

    }
}
