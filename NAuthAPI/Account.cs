using System.Security.Claims;

namespace NAuthAPI
{
    public class Account
    {
        public ClaimsIdentity Identity { get; set; }
        public string Hash { get; set; }
        public string Salt { get; set; }
        public bool IsBlocked { get; set; }
        public byte Attempts { get; set; }

        public Account(ClaimsIdentity identity, string hash, string salt, bool isBlocked, byte attempts)
        {
            Identity = identity;
            Hash = hash;
            Salt = salt;
            IsBlocked = isBlocked;
            Attempts = attempts;
        }
    }
}
