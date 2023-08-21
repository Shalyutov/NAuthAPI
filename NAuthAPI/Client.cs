namespace NAuthAPI
{
    public class Client
    {
        public string? Name { get; set; }
        public string? Secret { get; set; }
        public bool IsValid { get; set; }
        public bool IsTrusted { get; set; }
        public IEnumerable<string> Scopes { get; set; }

        public Client(string? name, string? secret, bool valid, bool trust, IEnumerable<string> scopes)
        {
            Name = name;
            Secret = secret;
            IsValid = valid;
            IsTrusted = trust;
            Scopes = scopes;
        }
        public Client()
        {
            Name = string.Empty;
            Secret = string.Empty;
            IsValid = false;
            IsTrusted = false;
            Scopes = new List<string>();
        }
        public static async Task<bool> Authenticate(AppContext _database, string client, string secret)
        {
            try
            {
                await GetClientAsync(_database, client, secret);
                return true;
            }
            catch(Exception)
            {
                return false;
            }
        }
        public static async Task<bool> TrustAuthenticate(AppContext _database, string client, string secret)
        {
            try
            {
                Client _client = await GetClientAsync(_database, client, secret);
                return _client.IsValid;
            }
            catch (Exception)
            {
                return false;
            }
        }
        public static async Task<Client> GetClientAsync(AppContext _database, string client, string secret)
        {
            if (string.IsNullOrEmpty(client) || string.IsNullOrEmpty(secret))
            {
                throw new Exception("Нет данных для авторизации клиентского приложения");
            }
                
            if (_database == null)
            {
                throw new Exception("Драйвер базы данных не запущен");
            }
            
            Client? _client = await _database.GetClient(client);
            if (_client != null)
            {
                if (_client.IsValid)
                {
                    if (_client.Secret == secret)
                    {
                        return _client;
                    }
                    else
                    {
                        throw new Exception("Клиентское приложение не авторизовано");
                    }
                }
                else
                {
                    throw new Exception("Клиентское приложение заблокировано");
                }
            }
            else
            {
                throw new Exception("Клиентского приложения не существует");
            }
        }
    }
}