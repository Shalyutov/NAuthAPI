using Microsoft.IdentityModel.Tokens;
using System.IdentityModel.Tokens.Jwt;
using System.Security.Claims;
using System.Text;
using Ydb.Sdk;

namespace NAuthAPI
{
    public class KeyLakeService
    {
        private readonly HttpClient _httpClient;
        private string _apiKey;
        private readonly string _issuer;
        private readonly string _audience;
        private readonly SymmetricSecurityKey key;

        public KeyLakeService(HttpClient httpClient, string lake, string issuer, string audience, string authKey)
        {
            _httpClient = httpClient;
            _httpClient.BaseAddress = new Uri(lake);
            _httpClient.Timeout = TimeSpan.FromSeconds(10);
            _issuer = issuer;
            _audience = audience;
            key = new SymmetricSecurityKey(Convert.FromBase64String(authKey));
            _apiKey = GetAccessToken(key);
        }
        private string GetAccessToken(SymmetricSecurityKey key)
        {
            var now = DateTime.UtcNow;
            var jwt = new JwtSecurityToken(
                _issuer,
                _audience,
                new List<Claim>() { new Claim(ClaimTypes.NameIdentifier, "federation") },
                now,
                now.Add(TimeSpan.FromMinutes(10)),
                new SigningCredentials(key, SecurityAlgorithms.HmacSha256));
            var token = new JwtSecurityTokenHandler().WriteToken(jwt);
            return token;
        }
        public async Task<string> CreateKey(string id)
        {
            if (_apiKey.IsNullOrEmpty())
                _apiKey = GetAccessToken(key);
            var request = new HttpRequestMessage(HttpMethod.Post, $"key/{id}")
            {
                Headers =
                {
                    Authorization = new System.Net.Http.Headers.AuthenticationHeaderValue("Bearer", _apiKey)
                }
            };
            var result = await _httpClient.SendAsync(request);
            if (result.StatusCode == System.Net.HttpStatusCode.OK)
            {
                string key = await result.Content.ReadAsStringAsync();
                return new StringBuilder(key).Replace("\"", "").ToString();
            }
            else if (result.StatusCode == System.Net.HttpStatusCode.Unauthorized)
            {
                _apiKey = string.Empty;
                throw new Exception("Ключ не авторизован");
            }
            else if (result.StatusCode == System.Net.HttpStatusCode.BadRequest)
            {
                throw new Exception("Ключ уже создан");
            }
            else
            {
                throw new Exception("Произошла ошибка при обработке запроса");
            }
        }
        public async Task<string> GetKey(string id)
        {
            if (_apiKey.IsNullOrEmpty())
                _apiKey = GetAccessToken(key);
            var request = new HttpRequestMessage(HttpMethod.Get, $"key/{id}")
            {
                Headers =
                {
                    Authorization = new System.Net.Http.Headers.AuthenticationHeaderValue("Bearer", _apiKey)
                }
            };
            var result = await _httpClient.SendAsync(request);
            if (result.StatusCode == System.Net.HttpStatusCode.OK)
            {
                string key = await result.Content.ReadAsStringAsync();
                return new StringBuilder(key).Replace("\"", "").ToString();
            }
            else if (result.StatusCode == System.Net.HttpStatusCode.Unauthorized)
            {
                _apiKey = string.Empty;
                throw new Exception("Ключ не авторизован");
            }
            else if (result.StatusCode == System.Net.HttpStatusCode.BadRequest)
            {
                throw new Exception("Ключ ещё не создан");
            }
            else
            {
                throw new Exception("Произошла ошибка при обработке запроса");
            }
        }
        public async Task<bool> DeleteKey(string id)
        {
            if (_apiKey.IsNullOrEmpty())
                _apiKey = GetAccessToken(key);
            var request = new HttpRequestMessage(HttpMethod.Get, $"key/{id}")
            {
                Headers =
                {
                    Authorization = new System.Net.Http.Headers.AuthenticationHeaderValue("Bearer", _apiKey)
                }
            };
            var result = await _httpClient.SendAsync(request);
            if (result.StatusCode == System.Net.HttpStatusCode.Accepted)
            {
                return true;
            }
            else if (result.StatusCode == System.Net.HttpStatusCode.Unauthorized)
            {
                _apiKey = string.Empty;
                throw new Exception("Ключ не авторизован");
            }
            else if (result.StatusCode == System.Net.HttpStatusCode.BadRequest)
            {
                throw new Exception("Ключ ещё не создан");
            }
            else
            {
                throw new Exception("Произошла ошибка при обработке запроса");
            }
        }
    }
}
