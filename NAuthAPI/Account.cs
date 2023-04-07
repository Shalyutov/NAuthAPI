using System.Security.Claims;

namespace NAuthAPI
{
    public class Account
    {
        public ClaimsIdentity Identity { get; set; }
        public string Hash { get; set; }
        public string Salt { get; set; }

        public Account(ClaimsIdentity identity, string hash, string salt)
        {
            Identity = identity;
            Hash = hash;
            Salt = salt;
        }
    }
}
