using ExampleApp.Identity;
using System;

namespace ExampleApp.Services {

    public interface ISMSSender {

        public void SendMessage(AppUser user, params string[] body);
    }

    public class ConsoleSMSSender : ISMSSender {

        public void SendMessage(AppUser user, params string[] body) {
            Console.WriteLine("--- SMS Starts ---");
            Console.WriteLine($"To: {user.PhoneNumber}");
            foreach (string str in body) {
                Console.WriteLine(str);
            }
            Console.WriteLine("--- SMS Ends ---");
        }
    }
}
