using Microsoft.AspNetCore.Authentication;
using Microsoft.AspNetCore.DataProtection;
using Microsoft.Extensions.Options;
using System.Security.Claims;
using System.Text.Json;

namespace ExampleApp.Custom {

    public class GoogleOptions : ExternalAuthOptions {
        public override string RedirectPath { get; set; } = "/signin-google";
        public override string AuthenticationUrl =>
            "https://accounts.google.com/o/oauth2/v2/auth";
        public override string ExchangeUrl =>
            "https://www.googleapis.com/oauth2/v4/token";
        public override string DataUrl =>
             "https://www.googleapis.com/oauth2/v2/userinfo";
    }

    public class GoogleHandler : ExternalAuthHandler {

        public GoogleHandler(IOptions<GoogleOptions> options,
            IDataProtectionProvider dp,
            ILogger<GoogleHandler> logger) : base(options, dp, logger) { }

        protected override IEnumerable<Claim> GetClaims(JsonDocument jsonDoc) {
            List<Claim> claims = new List<Claim>();
            string? value;
            if ((value = jsonDoc.RootElement.GetString("id")) != null) {
                claims.Add(new Claim(ClaimTypes.NameIdentifier, value));
            }
            if ((value = jsonDoc.RootElement.GetString("name")) != null) {
                claims.Add(new Claim(ClaimTypes.Name, value));
            }
            if ((value = jsonDoc.RootElement.GetString("email")) != null) {
                claims.Add(new Claim(ClaimTypes.Email, value));
            }
            return claims;
        }

        protected async override Task<string> GetAuthenticationUrl(
                AuthenticationProperties? properties) {
            if (CheckCredentials()) {
                return await base.GetAuthenticationUrl(properties);
            } else {
                return string.Format(Options.ErrorUrlTemplate, ErrorMessage);
            }
        }

        private bool CheckCredentials() {
            string secret = Options.ClientSecret;
            string id = Options.ClientId;
            string defaultVal = "ReplaceMe";
            if (string.IsNullOrEmpty(secret) || string.IsNullOrEmpty(id)
                || defaultVal.Equals(secret) || defaultVal.Equals(secret)) {
                ErrorMessage = "External Authentication Secret or ID Not Set";
                Logger.LogError("External Authentication Secret or ID Not Set");
                return false;
            }
            return true;
        }
    }
}
