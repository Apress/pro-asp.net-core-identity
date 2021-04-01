using Microsoft.AspNetCore.Http;
using System.Threading.Tasks;

namespace ExampleApp {

    public class SecretEndpoint {

        public static async Task Endpoint(HttpContext context) {
            await context.Response.WriteAsync("This is the secret message");
        }
    }
}
