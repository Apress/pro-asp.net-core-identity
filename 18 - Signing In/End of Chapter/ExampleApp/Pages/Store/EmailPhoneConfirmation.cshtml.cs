using ExampleApp.Identity;
using Microsoft.AspNetCore.Identity;
using Microsoft.AspNetCore.Mvc;
using Microsoft.AspNetCore.Mvc.RazorPages;
using System.Threading.Tasks;

namespace ExampleApp.Pages.Store {

    public class EmailPhoneConfirmationModel : PageModel {

        public EmailPhoneConfirmationModel(UserManager<AppUser> manager)
            => UserManager = manager;

        public UserManager<AppUser> UserManager { get; set; }

        [BindProperty(SupportsGet = true)]
        public string DataType { get; set; }

        [BindProperty(SupportsGet = true)]
        public string DataValue { get; set; }

        public bool IsEmail => DataType.Equals("email");

        public AppUser AppUser { get; set; }

        public async Task<IActionResult> OnGetAsync(string id) {
            AppUser = await UserManager.FindByIdAsync(id);
            if (DataValue != null && DataValue.Contains(':')) {
                string[] values = DataValue.Split(":");
                return await Validate(values[0], values[1]);
            }
            return Page();
        }

        public async Task<IActionResult> OnPostAsync(string id,
                string token, string dataValue) {
            AppUser = await UserManager.FindByIdAsync(id);
            return await Validate(dataValue, token);
        }

        private async Task<IActionResult> Validate(string value, string token) {
            IdentityResult result;
            if (IsEmail) {
                result = await UserManager.ChangeEmailAsync(AppUser, value, token);
            } else {
                result = await UserManager.ChangePhoneNumberAsync(AppUser, value,
                    token);
            }
            if (result.Succeeded) {
                return Redirect($"/users/edit/{AppUser.Id}");
            } else {
                foreach (IdentityError err in result.Errors) {
                    ModelState.AddModelError(string.Empty, err.Description);
                }
                return Page();
            }
        }
    }
}
