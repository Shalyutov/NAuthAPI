namespace NAuthAPI
{
    public class ClientValidator
    {
        public static async Task<bool> Authenticate(IAppContext _database, string client, string secret)
        {
            var _client = await GetClientAsync(_database, client);
            return _client.Secret == secret;
        }
        public static bool Authenticate(Client _client, string secret)
        {
            return _client.Secret == secret;
        }
        public static async Task<bool> IsTrustedClient(IAppContext _database, string client, string? secret = null)
        {
            Client _client = await GetClientAsync(_database, client);
            if (!string.IsNullOrEmpty(secret))
            {
                if (_client.Secret != secret)
                {
                    throw new Exception("Ошибка авторизации клиентского приложения");
                }
            }
            return _client.IsTrusted;
        }
        public static async Task<bool> IsValidClient(IAppContext _database, string client, string? secret = null)
        {
            Client _client = await GetClientAsync(_database, client);
            if (!string.IsNullOrEmpty(secret))
            {
                if (_client.Secret != secret)
                {
                    throw new Exception("Ошибка авторизации клиентского приложения");
                }
            }
            return _client.IsValid;
        }
        public static async Task<bool> IsTrustedValidClient(IAppContext _database, string client, string? secret = null)
        {
            Client _client = await GetClientAsync(_database, client);
            if (!string.IsNullOrEmpty(secret))
            {
                if (_client.Secret != secret)
                {
                    throw new Exception("Ошибка авторизации клиентского приложения");
                }
            }
            return _client.IsTrusted && _client.IsValid;
        }
        public static async Task<Client> GetClientAsync(IAppContext _database, string client)
        {
            if (string.IsNullOrEmpty(client))
            {
                throw new Exception("Предоставьте клиентское приложение");
            }

            if (_database == null)
            {
                throw new Exception("Драйвер базы данных не запущен");
            }

            Client? _client = await _database.GetClient(client) ?? throw new Exception("Клиентского приложения не существует");
            if (!_client.IsValid)
            {
                throw new Exception("Клиентское приложение заблокировано");
            }
            return _client;
        }
    }
}
