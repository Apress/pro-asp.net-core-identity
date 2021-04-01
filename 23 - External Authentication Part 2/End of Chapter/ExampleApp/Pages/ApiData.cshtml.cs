using ExampleApp.Identity;
using Microsoft.AspNetCore.Authentication;
using Microsoft.AspNetCore.Identity;
using Microsoft.AspNetCore.Mvc.RazorPages;
using System.Net.Http;
using System.Net.Http.Headers;
using System.Text.Json;
using System.Threading.Tasks;

namespace ExampleApp.Pages {

    public class ApiDataModel : PageModel {

        public ApiDataModel(UserManager<AppUser> userManager) {
            UserManager = userManager;
        }

        public UserManager<AppUser> UserManager { get; set; }

        public string Data { get; set; } = "No Data";

        public async Task OnGetAsync() {
            AppUser user = await UserManager.GetUserAsync(HttpContext.User);
            if (user != null) {
                string token = await UserManager.GetAuthenticationTokenAsync
                    (user, "demoAuth", "access_token");
                if (!string.IsNullOrEmpty(token)) {
                    HttpRequestMessage msg = new HttpRequestMessage(
                        HttpMethod.Get,
                        "http://localhost:5000/api/DemoExternalApi");
                    msg.Headers.Authorization = new AuthenticationHeaderValue
                        ("Bearer", token);
                    HttpResponseMessage resp
                        = await new HttpClient().SendAsync(msg);
                    JsonDocument doc = JsonDocument.Parse(await
                        resp.Content.ReadAsStringAsync());
                    Data = doc.RootElement.GetString("data");
                }
            }
        }
    }
}
