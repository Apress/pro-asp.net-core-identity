using Microsoft.AspNetCore.Identity;
using System.Collections.Generic;
using System.Linq;
using System.Security.Claims;

namespace ExampleApp.Identity.Store {

    public partial class UserStore {

        public ILookupNormalizer Normalizer { get; set; }

        public IPasswordHasher<AppUser> PasswordHasher { get; set; }

        public UserStore(ILookupNormalizer normalizer,
                IPasswordHasher<AppUser> passwordHasher) {
            Normalizer = normalizer;
            PasswordHasher = passwordHasher;
            SeedStore();
        }

        private void SeedStore() {

            var customData = new Dictionary<string, (string food, string hobby)> {
                { "Alice", ("Pizza", "Running") },
                { "Bob", ("Ice Cream", "Cinema") },
                { "Charlie", ("Burgers", "Cooking") }
            };
            var twoFactorUsers = new[] { "Alice", "Charlie" };
            var authenticatorKeys = new Dictionary<string, string> {
                {"Alice", "A4GG2BNKJNKKFOKGZRGBVUYIAJCUHEW7" }
            };
            var codes = new[] { "abcd1234", "abcd5678" };
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
                    Hobby = customData[name].hobby,
                    SecurityStamp = "InitialStamp",
                    TwoFactorEnabled = twoFactorUsers.Any(tfName => tfName == name)
                };
                user.Claims = UsersAndClaims.UserData[user.UserName]
                    .Select(role => new Claim(ClaimTypes.Role, role)).ToList();
                user.PasswordHash = PasswordHasher.HashPassword(user, "MySecret1$");
                if (authenticatorKeys.ContainsKey(name)) {
                    user.AuthenticatorKey = authenticatorKeys[name];
                    user.AuthenticatorEnabled = true;
                }
                users.TryAdd(user.Id, user);
                recoveryCodes.Add(user.Id, codes.Select(c =>
                    new RecoveryCode() { Code = c }).ToArray());
            }
        }
    }
}
