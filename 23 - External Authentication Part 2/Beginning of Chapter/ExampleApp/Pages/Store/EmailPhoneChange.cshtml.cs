using ExampleApp.Identity;
using ExampleApp.Services;
using Microsoft.AspNetCore.Identity;
using Microsoft.AspNetCore.Mvc;
using Microsoft.AspNetCore.Mvc.RazorPages;
using System.Threading.Tasks;

namespace ExampleApp.Pages.Store {

    public class EmailPhoneChangeModel : PageModel {

        public EmailPhoneChangeModel(UserManager<AppUser> manager,
                IEmailSender email, ISMSSender sms) {
            UserManager = manager;
            EmailSender = email;
            SMSSender = sms;
        }

        public UserManager<AppUser> UserManager { get; set; }
        public IEmailSender EmailSender { get; set; }
        public ISMSSender SMSSender { get; set; }

        [BindProperty(SupportsGet = true)]
        public string DataType { get; set; }

        public bool IsEmail => DataType.Equals("email");

        public AppUser AppUser { get; set; }

        public string LabelText => DataType ==
            "email" ? "Email Address" : "Phone Number";

        public string CurrentValue => IsEmail
             ? AppUser.EmailAddress : AppUser.PhoneNumber;

        public async Task OnGetAsync(string id, string data) {
            AppUser = await UserManager.FindByIdAsync(id);
        }

        public async Task<IActionResult> OnPost(string id, string dataValue) {
            AppUser = await UserManager.FindByIdAsync(id);
            if (IsEmail) {
                string token = await UserManager
                    .GenerateChangeEmailTokenAsync(AppUser, dataValue);
                EmailSender.SendMessage(AppUser, "Confirm Email",
                    "Please click the link to confirm your email address:",
                 $"http://localhost:5000/validate/{id}/email/{dataValue}:{token}");
            } else {
                string token = await UserManager
                    .GenerateChangePhoneNumberTokenAsync(AppUser, dataValue);
                SMSSender.SendMessage(AppUser,
                    $"Your confirmation token is {token}");
            }
            return RedirectToPage("EmailPhoneConfirmation",
                new { id = id, dataType = DataType, dataValue = dataValue });
        }
    }
}
