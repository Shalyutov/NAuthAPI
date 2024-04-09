namespace NAuthAPI
{
    public interface IAppContext
    {
        public Task<bool> CreateTables();

        #region Account Data
        public Task<Account?> GetAccount(string username);
        public Task<User?> GetUser(string id);
        public Task<bool> IsUsernameExists(string username);
        #endregion

        #region Account Management
        public Task<bool> CreateIdentity(Account account, User user);
        public Task<bool> UpdateUser(string id, Dictionary<string, string> claims);
        public Task<bool> DeleteAccount(string user);
        #endregion

        #region Key Management
        public Task<bool> CreateAuthKey(string key, string audience, string user);
        public Task<bool> DeleteAuthKey(string key);
        public Task<bool> DeleteUserAuthKeys(string user);
        public Task<bool> IsKeyValid(string keyId);
        public Task<List<string>> GetUserKeys(string user);
        #endregion

        #region Client Management
        public Task<Client?> GetClient(string name);
        //TODO Delete update create
        #endregion

        #region User Security
        public Task<List<Attempt>> GetAttempts(string user);
        public Task<bool> AddAttempt(string user, bool success);
        public Task<bool> SetPasswordHash(string id, byte[] hash);
        #endregion

        #region Data Accept
        public Task<bool> CreateAccept(string user, string client, string scope);
        public Task<List<string>> GetAccepts(string user, string client);
        public Task<bool> DeleteAccept(string user, string client, string type);
        public Task<bool> DeleteAccept(string user, string client);
        #endregion

        #region Data Management
        public Task<Dictionary<string, string>> GetClaims(IEnumerable<string> claimTypes, string user);
        public Task<bool> SetClaim(string user, string issuer, string type, string value);
        public Task<bool> DeleteClaim(string user, string issuer, string type);
        #endregion

        #region Authorization Management
        public Task<bool> CreateRequest(Request request);
        public Task<Request?> GetRequest(string client, string code_verifier);
        public Task<Request?> GetRequestByCode(string code);
        public Task<bool> DeleteRequest(string code);
        #endregion
    }
}
