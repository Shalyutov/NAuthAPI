using Newtonsoft.Json;
using Newtonsoft.Json.Linq;
using System.Security.Cryptography;
using Vault;
using Vault.Client;
using Vault.Model;
using Yandex.Cloud.Generated;

namespace NAuthAPI
{
    public class VaultService : IKVEngine
    {
        private readonly VaultClient client;
        public VaultService(string address, string token)
        {
            VaultConfiguration config = new(address);
            client = new VaultClient(config);
            client.SetToken(token);
        }
        public byte[] CreateKey(string key)
        {
            byte[] payload = RandomNumberGenerator.GetBytes(32);
            var secretData = new Dictionary<string, byte[]> { { "key", payload } };
            var kvRequestData = new KvV2WriteRequest(secretData);
            client.Secrets.KvV2Write(key, kvRequestData, "kv");
            return payload;
        }

        public bool DeleteKey(string key)
        {
            VaultResponse<object> resp = client.Secrets.KvV2Delete($"{key}", "kv");
            return resp.Data != null;
        }

        public byte[] GetKey(string key)
        {
            VaultResponse<KvV2ReadResponse> resp = client.Secrets.KvV2Read($"{key}", "kv");
            var res = JObject.Parse(resp.Data.ToJson());
            return (byte[])res["data"]!["key"]!;
        }
        public string GetPepper()
        {
            VaultResponse<KvV2ReadResponse> resp = client.Secrets.KvV2Read($"Federation", "kv");
            var res = JObject.Parse(resp.Data.ToJson());
            return (string)res["data"]!["Pepper"]!;
        }
        
    }
}
