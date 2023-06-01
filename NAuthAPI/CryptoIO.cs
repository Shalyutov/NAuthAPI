using Microsoft.IdentityModel.Tokens;

namespace NAuthAPI
{
    public class CryptoIO
    {
        public static async Task<SymmetricSecurityKey> CreateSecurityKey(byte[] bytes)
        {
            var key = new SymmetricSecurityKey(bytes)
            {
                KeyId = Guid.NewGuid().ToString()
            };
            await File.WriteAllTextAsync($"keys/{key.KeyId}.key", Convert.ToBase64String(key.Key));
            return key;
        }
        public static void DeleteSecurityKey(string keyId)
        {
            File.Delete($"keys/{keyId}.key");
        }
    }
}
