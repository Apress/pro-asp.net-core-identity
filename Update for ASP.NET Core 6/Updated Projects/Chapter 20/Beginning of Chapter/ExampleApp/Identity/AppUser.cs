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
        public string? PasswordHash { get; set; }
    }
}
