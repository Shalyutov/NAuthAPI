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
        public byte[] CreateKey(string key)
        {
            byte[] payload = RandomNumberGenerator.GetBytes(32);
            File.WriteAllBytes($"keys/{key}.key", payload);
            return payload;
        }

        public bool DeleteKey(string key)
        {
            File.Delete($"keys/{key}.key");
            return true;
        }

        public byte[] GetKey(string key)
        {
            byte[] payload = File.ReadAllBytes($"keys/{key}.key");
            return payload;
        }

        public string GetPepper()
        {
            return "Ppdofiiennhuvygdfg29598efgj]{hijuhufrg--*+54575(*&^*^%";
        }
    }
}
