using Microsoft.AspNetCore.Authentication;
using Microsoft.AspNetCore.Http;
using System.Threading.Tasks;
using System.Security.Claims;
using Microsoft.AspNetCore.Identity;
using Microsoft.Extensions.Options;
using System.Collections.Generic;
using Microsoft.AspNetCore.DataProtection;
using System.Net.Http;
using System.Net.Http.Json;
using System.Text.Json;
using Microsoft.Extensions.Logging;
using System.Net.Http.Headers;

namespace ExampleApp.Custom {

    public class ExternalAuthOptions {
        public string ClientId { get; set; } = "MyClientID";
        public string ClientSecret { get; set; } = "MyClientSecret";

        public virtual string RedirectRoot { get; set; } = "http://localhost:5000";
        public virtual string RedirectPath { get; set; } = "/signin-external";
        public virtual string Scope { get; set; } = "openid email profile";
        public virtual string StateHashSecret { get; set; } = "mysecret";

        public virtual string AuthenticationUrl { get; set; }
            = "http://localhost:5000/DemoExternalAuth/authenticate";
        public virtual string ExchangeUrl { get; set; }
            = "http://localhost:5000/DemoExternalAuth/exchange";
        public virtual string ErrorUrlTemplate { get; set; }
            = "/externalsignin?error={0}";
        public virtual string DataUrl { get; set; }
            = "http://localhost:5000/DemoExternalAuth/data";

    }

    public class ExternalAuthHandler : IAuthenticationRequestHandler {

        public ExternalAuthHandler(IOptions<ExternalAuthOptions> options,
                IDataProtectionProvider dp, ILogger<ExternalAuthHandler> logger) {
            Options = options.Value;
            DataProtectionProvider = dp;
            Logger = logger;
        }

        public AuthenticationScheme? Scheme { get; set; }
        public HttpContext? Context { get; set; }
        public ExternalAuthOptions Options { get; set; }
        public IDataProtectionProvider DataProtectionProvider { get; set; }
        public PropertiesDataFormat? PropertiesFormatter { get; set; }
        public ILogger<ExternalAuthHandler> Logger { get; set; }
        public string? ErrorMessage { get; set; }

        public Task InitializeAsync(AuthenticationScheme scheme,
                HttpContext context) {
            Scheme = scheme;
            Context = context;
            PropertiesFormatter = new PropertiesDataFormat(DataProtectionProvider.CreateProtector(typeof(ExternalAuthOptions).FullName ?? "Unknown"));
            return Task.CompletedTask;
        }

        public Task<AuthenticateResult> AuthenticateAsync() {
            return Task.FromResult(AuthenticateResult.NoResult());
        }

        public async Task ChallengeAsync(AuthenticationProperties? properties) {
            Context?.Response.Redirect(await GetAuthenticationUrl(properties));
        }

        protected virtual Task<string>
                GetAuthenticationUrl(AuthenticationProperties? properties) {
            Dictionary<string, string?> qs = new();
            qs.Add("client_id", Options.ClientId);
            qs.Add("redirect_uri", Options.RedirectRoot + Options.RedirectPath);
            qs.Add("scope", Options.Scope);
            qs.Add("response_type", "code");
            qs.Add("state", PropertiesFormatter!.Protect(properties!));
            return Task.FromResult(Options.AuthenticationUrl + QueryString.Create(qs));
        }

        public Task ForbidAsync(AuthenticationProperties? properties) {
            return Task.CompletedTask;
        }

        public virtual async Task<bool> HandleRequestAsync() {
            if (Context?.Request.Path.Equals(Options.RedirectPath) == true) {
                string? authCode = await GetAuthenticationCode();
                (string? token, string? state) = await GetAccessToken(authCode);
                if (!string.IsNullOrEmpty(token)) {
                    IEnumerable<Claim>? claims = await GetUserData(token);
                    if (claims != null) {
                        ClaimsIdentity identity = new ClaimsIdentity(Scheme?.Name);
                        identity.AddClaims(claims);
                        ClaimsPrincipal claimsPrincipal
                            = new ClaimsPrincipal(identity);
                        AuthenticationProperties? props
                             = PropertiesFormatter?.Unprotect(state);
                        props?.StoreTokens(new[] { new AuthenticationToken {
                            Name = "access_token", Value = token } });
                        await Context.SignInAsync(IdentityConstants.ExternalScheme,
                            claimsPrincipal, props);
                        Context.Response.Redirect(props?.RedirectUri ?? "/");
                        return true;
                    }
                }
                Context.Response.Redirect(string.Format(Options.ErrorUrlTemplate,
                     ErrorMessage));
                return true;
            }
            return false;
        }

        protected virtual Task<string?> GetAuthenticationCode() {
            return Task.FromResult(Context?.Request.Query["code"].ToString());
        }

        protected virtual async Task<(string? code, string? state)>
                GetAccessToken(string? code) {
            string? state = Context?.Request.Query["state"];
            HttpClient httpClient = new HttpClient();
            httpClient.DefaultRequestHeaders.Add("Accept", "application/json");
            HttpResponseMessage response = await httpClient
                .PostAsJsonAsync(Options.ExchangeUrl,
                    new {
                        code,
                        redirect_uri = Options.RedirectRoot + Options.RedirectPath,
                        client_id = Options.ClientId,
                        client_secret = Options.ClientSecret,
                        state,
                        grant_type = "authorization_code",
                    });
            string jsonData = await response.Content.ReadAsStringAsync();
            JsonDocument jsonDoc = JsonDocument.Parse(jsonData);
            string? error = jsonDoc.RootElement.GetString("error");
            if (error != null) {
                ErrorMessage = "Access Token Error";
                Logger.LogError(ErrorMessage);
                Logger.LogError(jsonData);
            }
            string? token = jsonDoc.RootElement.GetString("access_token");
            string? jsonState = jsonDoc.RootElement.GetString("state") ?? state;
            return error == null ? (token, state) : (null, null);
        }

        protected virtual async Task<IEnumerable<Claim>?>
          GetUserData(string accessToken) {
            HttpRequestMessage msg = new HttpRequestMessage(HttpMethod.Get,
                Options.DataUrl);
            msg.Headers.Authorization = new AuthenticationHeaderValue("Bearer",
                 accessToken);
            HttpResponseMessage response = await new HttpClient().SendAsync(msg);
            string jsonData = await response.Content.ReadAsStringAsync();
            JsonDocument jsonDoc = JsonDocument.Parse(jsonData);

            var error = jsonDoc.RootElement.GetString("error");
            if (error != null) {
                ErrorMessage = "User Data Error";
                Logger.LogError(ErrorMessage);
                Logger.LogError(jsonData);
                return null;
            } else {
                return GetClaims(jsonDoc);
            }
        }

        protected virtual IEnumerable<Claim> GetClaims(JsonDocument jsonDoc) {
            List<Claim> claims = new List<Claim>();
            string? val;
            if ((val = jsonDoc.RootElement.GetString("id")) != null) {
                claims.Add(new Claim(ClaimTypes.NameIdentifier, val));
            }
            if ((val = jsonDoc.RootElement.GetString("name")) != null) {
                claims.Add(new Claim(ClaimTypes.Name, val));
            }
            if ((val = jsonDoc.RootElement.GetString("emailAddress")) != null) {
                claims.Add(new Claim(ClaimTypes.Email, val));
            }
            return claims;
        }
    }
}
