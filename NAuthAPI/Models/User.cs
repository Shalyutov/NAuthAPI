namespace NAuthAPI
{
    public class User(string id, string? surname, string? name, string? lastName, string? email, ulong? phone, string? gender)
    {
        public string Id { get; set; } = id;
        public string? Surname { get; set; } = surname;
        public string? Name { get; set; } = name;
        public string? LastName { get; set; } = lastName;
        public string? Email { get; set; } = email;
        public ulong? Phone { get; set; } = phone;
        public string? Gender { get; set; } = gender;
    }
}
