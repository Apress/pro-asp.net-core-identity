using Microsoft.AspNetCore.Identity;

namespace ExampleApp.Identity.Store {

    public interface IReadableUserTwoFactorRecoveryCodeStore
            : IUserTwoFactorRecoveryCodeStore<AppUser> {
        Task<IEnumerable<RecoveryCode>> GetCodesAsync(AppUser user);
    }

    public partial class UserStore : IReadableUserTwoFactorRecoveryCodeStore {
        private IDictionary<string, IEnumerable<RecoveryCode>> recoveryCodes
            = new Dictionary<string, IEnumerable<RecoveryCode>>();

        public async Task<int> CountCodesAsync(AppUser user, CancellationToken token)
            => (await GetCodesAsync(user)).Where(code => !code.Redeemed).Count();


        public Task<IEnumerable<RecoveryCode>> GetCodesAsync(AppUser user) =>
            Task.FromResult(recoveryCodes.ContainsKey(user.Id)
                ? recoveryCodes[user.Id] : Enumerable.Empty<RecoveryCode>());

        public async Task<bool> RedeemCodeAsync(AppUser user, string code,
                CancellationToken token) {
            RecoveryCode? rc = (await GetCodesAsync(user)).FirstOrDefault(rc => rc.Code == code && !rc.Redeemed);
            if (rc != null) {
                rc.Redeemed = true;
                return true;
            }
            return false;
        }

        public Task ReplaceCodesAsync(AppUser user, IEnumerable<string>
                recoveryCodes, CancellationToken token) {
            this.recoveryCodes[user.Id] = recoveryCodes
                .Select(rc => new RecoveryCode { Code = rc, Redeemed = false });
            return Task.CompletedTask;
        }
    }
}
