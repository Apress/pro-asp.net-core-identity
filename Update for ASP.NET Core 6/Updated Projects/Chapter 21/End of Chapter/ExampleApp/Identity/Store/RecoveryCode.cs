namespace ExampleApp.Identity.Store {

    public class RecoveryCode {

        public string Code { get; set; } = String.Empty;
        public bool Redeemed { get; set; }
    }
}
