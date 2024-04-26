using Yandex.Cloud.Mdb.Clickhouse.V1;

namespace NAuthAPI
{
    public class Account(string id, string username, byte[] hash, byte[] salt, bool isBlocked, string grant, DateTime access) : IEquatable<Account?>
    {
        public string Id { get; set; } = id;
        public string Username { get; set; } = username;
        public byte[] Hash { get; set; } = hash;
        public byte[] Salt { get; set; } = salt;
        public bool IsBlocked { get; set; } = isBlocked;
        public string Grant { get; set; } = grant;
        public DateTime Access { get; set; } = access;

        public override bool Equals(object? obj)
        {
            return Equals(obj as Account);
        }

        public bool Equals(Account? other)
        {
            return other is not null &&
                   Id == other.Id &&
                   Username == other.Username;
        }

        public override int GetHashCode()
        {
            return HashCode.Combine(Id, Username);
        }

        public static bool operator ==(Account? left, Account? right)
        {
            return EqualityComparer<Account>.Default.Equals(left, right);
        }

        public static bool operator !=(Account? left, Account? right)
        {
            return !(left == right);
        }

    }
}
