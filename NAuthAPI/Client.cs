namespace NAuthAPI
{
    public class Client
    {
        public string? Name { get; set; }
        public string? Secret { get; set; }
        public bool IsValid { get; set; }
        public bool IsImplementation { get; set; }
        public List<string> Scopes { get; set; }

        public Client(string? name, string? secret, bool isValid, bool isImplementation, List<string> scopes)
        {
            Name = name;
            Secret = secret;
            IsValid = isValid;
            IsImplementation = isImplementation;
            Scopes = scopes;
        }
        public static async Task<Client?> GetClientAsync(AppContext _database, string client_id, string client_secret)
        {
            if (client_id == "" || client_secret == "")
                return null;
            if (_database == null)
                return null;

            var client = await _database.GetClient(client_id);
            if (client == null)
                return null;

            if (client.Secret == client_secret && client.IsValid)
                return client;
            else
                return null;
        }
    }
}