using Microsoft.AspNetCore.Identity;
using System;
using System.Security.Cryptography;
using System.Text;

namespace ExampleApp.Identity {
    public class SimplePasswordHasher : IPasswordHasher<AppUser> {

        public SimplePasswordHasher(ILookupNormalizer normalizer)
            => Normalizer = normalizer;

        private ILookupNormalizer Normalizer { get; set; }

        public string HashPassword(AppUser user, string password) {
            HMACSHA256 hashAlgorithm =
                new HMACSHA256(Encoding.UTF8.GetBytes(user.Id));
            return BitConverter.ToString(hashAlgorithm.ComputeHash(
                    Encoding.UTF8.GetBytes(password)));
        }

        public PasswordVerificationResult VerifyHashedPassword(AppUser user,
            string storedHash, string password)
                => HashPassword(user, password).Equals(storedHash)
                    ? PasswordVerificationResult.Success
                    : PasswordVerificationResult.Failed;
    }
}
