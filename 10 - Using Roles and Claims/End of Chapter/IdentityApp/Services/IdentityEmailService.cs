using Microsoft.AspNetCore.Http;
using Microsoft.AspNetCore.Identity;
using Microsoft.AspNetCore.Identity.UI.Services;
using Microsoft.AspNetCore.Routing;
using System.Threading.Tasks;

namespace IdentityApp.Services {

    public class IdentityEmailService {

        public IdentityEmailService(IEmailSender sender,
                UserManager<IdentityUser> userMgr,
                IHttpContextAccessor contextAccessor,
                LinkGenerator generator,
                TokenUrlEncoderService encoder) {
            EmailSender = sender;
            UserManager = userMgr;
            ContextAccessor = contextAccessor;
            LinkGenerator = generator;
            TokenEncoder = encoder;
        }

        public IEmailSender EmailSender { get; set; }
        public UserManager<IdentityUser> UserManager { get; set; }
        public IHttpContextAccessor ContextAccessor { get; set; }
        public LinkGenerator LinkGenerator { get; set; }
        public TokenUrlEncoderService TokenEncoder { get; set; }

        private string GetUrl(string emailAddress, string token, string page) {
            string safeToken = TokenEncoder.EncodeToken(token);
            return LinkGenerator.GetUriByPage(ContextAccessor.HttpContext, page,
                null, new { email = emailAddress, token = safeToken });
        }

        public async Task SendPasswordRecoveryEmail(IdentityUser user,
                string confirmationPage) {
            string token = await UserManager.GeneratePasswordResetTokenAsync(user);
            string url = GetUrl(user.Email, token, confirmationPage);
            await EmailSender.SendEmailAsync(user.Email, "Set Your Password",
                $"Please set your password by <a href={url}>clicking here</a>.");
        }

        public async Task SendAccountConfirmEmail(IdentityUser user,
                string confirmationPage) {
            string token =
                await UserManager.GenerateEmailConfirmationTokenAsync(user);
            string url = GetUrl(user.Email, token, confirmationPage);
            await EmailSender.SendEmailAsync(user.Email,
                "Complete Your Account Setup",
                $"Please set up your account by <a href={url}>clicking here</a>.");
        }
    }
}
