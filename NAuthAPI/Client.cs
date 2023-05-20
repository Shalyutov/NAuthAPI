namespace NAuthAPI
{
    public class Client
    {
        public string? Name { get; set; }
        public string? Secret { get; set; }
        public bool IsValid { get; set; }
        public bool IsImplementation { get; set; }
        public string? Scopes { get; set; }

        public Client(string? name, string? secret, bool isValid, bool isImplementation, string? scopes)
        {
            Name = name;
            Secret = secret;
            IsValid = isValid;
            IsImplementation = isImplementation;
            Scopes = scopes;
        }
    }
}