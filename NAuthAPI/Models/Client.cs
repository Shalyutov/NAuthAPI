namespace NAuthAPI
{
    public class Client(string name, string secret, bool isValid, bool isTrusted, IEnumerable<string> scopes, string callback)
    {
        public string Name { get; set; } = name;
        public string Secret { get; set; } = secret;
        public bool IsValid { get; set; } = isValid;
        public bool IsTrusted { get; set; } = isTrusted;
        public IEnumerable<string> Scopes { get; set; } = scopes;
        public string Callback { get; set; } = callback;
    }
}