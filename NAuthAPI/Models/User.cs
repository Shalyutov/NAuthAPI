
namespace NAuthAPI
{
    public class User(string id, string? surname, string? name, string? lastName, string? email, ulong? phone, string? gender) : IEquatable<User?>
    {
        public string Id { get; set; } = id;
        public string? Surname { get; set; } = surname;
        public string? Name { get; set; } = name;
        public string? LastName { get; set; } = lastName;
        public string? Email { get; set; } = email;
        public ulong? Phone { get; set; } = phone;
        public string? Gender { get; set; } = gender;

        public override bool Equals(object? obj)
        {
            return Equals(obj as User);
        }

        public bool Equals(User? other)
        {
            return other is not null &&
                   Id == other.Id &&
                   Surname == other.Surname &&
                   Name == other.Name &&
                   LastName == other.LastName &&
                   Email == other.Email &&
                   Phone == other.Phone &&
                   Gender == other.Gender;
        }

        public override int GetHashCode()
        {
            return HashCode.Combine(Id, Surname, Name, LastName, Email, Phone, Gender);
        }

        public static bool operator ==(User? left, User? right)
        {
            return EqualityComparer<User>.Default.Equals(left, right);
        }

        public static bool operator !=(User? left, User? right)
        {
            return !(left == right);
        }
    }
}
