using Microsoft.AspNetCore.Mvc.RazorPages;
using Microsoft.AspNetCore.Authorization;

namespace IdentityApp.Pages.Identity {

    [Authorize]
    public class UserPageModel : PageModel {

        // no methods or properties required
    }
}
