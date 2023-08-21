using System.Security.Cryptography;
using static Yandex.Cloud.Mdb.Clickhouse.V1.Config.ClickhouseConfig.Types.ExternalDictionary.Types.Structure.Types;

namespace NAuthAPI
{
    public class InternalService : IKVEngine
    {
        public InternalService()
        {
            if (!Directory.Exists("keys")) Directory.CreateDirectory("keys");
        }
        public string CreateKey(string key)
        {
            byte[] payload = RandomNumberGenerator.GetBytes(32);
            File.WriteAllBytes($"keys/{key}.key", payload);
            return Convert.ToBase64String(payload);
        }

        public bool DeleteKey(string key)
        {
            File.Delete($"keys/{key}.key");
            return true;
        }

        public string GetKey(string key)
        {
            byte[] payload = File.ReadAllBytes($"keys/{key}.key");
            return Convert.ToBase64String(payload);
        }

        public string GetPepper()
        {
            return "AMdjr86#675y=kdfnfg";
        }
    }
}
