using Microsoft.AspNetCore.Http;
using System.Threading.Tasks;
using Microsoft.AspNetCore.Authorization;

namespace ExampleApp {

    
    public class SecretEndpoint {

        [Authorize(Roles = "Administrator")]
        public static async Task Endpoint(HttpContext context) {
            await context.Response.WriteAsync("This is the secret message");
        }
    }
}
