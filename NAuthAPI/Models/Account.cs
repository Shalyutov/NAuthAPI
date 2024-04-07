using Yandex.Cloud.Mdb.Clickhouse.V1;

namespace NAuthAPI
{
    public class Account(string id, string username, byte[] hash, byte[] salt, bool isBlocked, byte attempts, string grant, DateTime access)
    {
        public string Id { get; set; } = id;
        public string Username { get; set; } = username;
        public byte[] Hash { get; set; } = hash;
        public byte[] Salt { get; set; } = salt;
        public bool IsBlocked { get; set; } = isBlocked;
        public byte Attempts { get; set; } = attempts;
        public string Grant { get; set; } = grant;
        public DateTime Access { get; set; } = access;
    }
}
