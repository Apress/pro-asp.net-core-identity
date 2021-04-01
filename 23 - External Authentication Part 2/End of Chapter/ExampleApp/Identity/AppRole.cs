using System;
using System.Collections.Generic;
using System.Security.Claims;

namespace ExampleApp.Identity {

    public class AppRole {

        public string Id { get; set; } = Guid.NewGuid().ToString();

        public string Name { get; set; }

        public string NormalizedName { get; set; }

        public IList<Claim> Claims { get; set; }
    }
}
