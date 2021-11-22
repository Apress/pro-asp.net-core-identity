using System.Security.Claims;

namespace ExampleApp.Identity {

    public class AppRole {

        public string Id { get; set; } = Guid.NewGuid().ToString();

        public string Name { get; set; } = String.Empty;

        public string NormalizedName { get; set; } = String.Empty;

        public IList<Claim> Claims { get; set; } = new List<Claim>();
    }
}
