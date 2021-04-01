using Microsoft.AspNetCore.Identity;
using Microsoft.AspNetCore.Mvc;
using System.ComponentModel.DataAnnotations;
using System.Threading.Tasks;
using SignInResult = Microsoft.AspNetCore.Identity.SignInResult;
using Microsoft.Extensions.Configuration;
using System.IdentityModel.Tokens.Jwt;
using Microsoft.IdentityModel.Tokens;
using System.Linq;
using System;
using System.Text;

namespace IdentityApp.Controllers {

    [ApiController]
    [Route("/api/auth")]
    public class ApiAuthController : ControllerBase {
        private SignInManager<IdentityUser> SignInManager;
        private UserManager<IdentityUser> UserManager;
        private IConfiguration Configuration;

        public ApiAuthController(SignInManager<IdentityUser> signMgr,
                UserManager<IdentityUser> usrMgr,
                IConfiguration config) {
            SignInManager = signMgr;
            UserManager = usrMgr;
            Configuration = config;
        }

        [HttpPost("signin")]
        public async Task<object> ApiSignIn(
                [FromBody] SignInCredentials creds) {
            IdentityUser user = await UserManager.FindByEmailAsync(creds.Email);
            SignInResult result = await SignInManager.CheckPasswordSignInAsync(user,
                creds.Password, true);
            if (result.Succeeded) {
                SecurityTokenDescriptor descriptor = new SecurityTokenDescriptor {
                    Subject = (await SignInManager.CreateUserPrincipalAsync(user))
                        .Identities.First(),
                    Expires = DateTime.Now.AddMinutes(int.Parse(
                        Configuration["BearerTokens:ExpiryMins"])),
                    SigningCredentials = new SigningCredentials(
                        new SymmetricSecurityKey(Encoding.UTF8.GetBytes(
                            Configuration["BearerTokens:Key"])),
                            SecurityAlgorithms.HmacSha256Signature)
                };
                JwtSecurityTokenHandler handler = new JwtSecurityTokenHandler();
                SecurityToken secToken = new JwtSecurityTokenHandler()
                    .CreateToken(descriptor);
                return new { success = true, token = handler.WriteToken(secToken) };
            }
            return new { success = false };
        }

        //[HttpPost("signout")]
        //public async Task<IActionResult> ApiSignOut() {
        //    await SignInManager.SignOutAsync();
        //    return Ok();
        //}
    }

    public class SignInCredentials {
        [Required]
        public string Email { get; set; }
        [Required]
        public string Password { get; set; }
    }
}
