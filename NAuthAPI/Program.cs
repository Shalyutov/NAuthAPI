using Microsoft.AspNetCore.Authentication.Cookies;
using Microsoft.AspNetCore.Authentication.JwtBearer;
using Microsoft.AspNetCore.Authentication.OAuth;
using Microsoft.AspNetCore.Authorization.Infrastructure;
using Microsoft.AspNetCore.DataProtection.AuthenticatedEncryption;
using Microsoft.IdentityModel.Tokens;
using NAuthAPI;
using NAuthAPI.Controllers;
using System.Security.Cryptography;
using Ydb.Sdk;
using Ydb.Sdk.Auth;
using Ydb.Sdk.Services.Table;
using Ydb.Sdk.Yc;

var builder = WebApplication.CreateBuilder(args);
builder.Configuration.AddEnvironmentVariables();

string keypath = builder.Configuration["AuthKey"] ?? "";
string endpoint = builder.Configuration["Endpoint"] ?? "";
string databasePath = builder.Configuration["Database"] ?? "";

AuthNames names = new()
{
    Issuer = builder.Configuration["Issuer"] ?? "NAuth API",
    Audience = builder.Configuration["Audience"] ?? "NAuth App"
};

string lake_auth = builder.Configuration["KeyLakeAuth"] ?? "";
string vault_auth = builder.Configuration["VaultAuth"] ?? "";
string kv_address = builder.Configuration["KVAddress"] ?? "";

ICredentialsProvider provider;
Driver? driver = null;
TableClient? tableClient = null;
NAuthAPI.AppContext? _database = null;

if (keypath != "") //Используем авторизованный ключ доступа если он задан в настройках приложения
{
    provider = new ServiceAccountProvider(keypath);
    await ((ServiceAccountProvider)provider).Initialize();
}
else
{
    provider = new AnonymousProvider(); //анонимная аутентификация по умолчанию если не задан ключ
}

for(int i = 0; i < 6; i++)//retry connect //переподключение
{
    try
    {
        var config = new DriverConfig(endpoint, databasePath, provider);
        driver = new Driver(config);
        await driver.Initialize();
        break;
    }
    catch(Exception)
    {
        Thread.Sleep(15000);
    }
}

if (driver != null)
{
    tableClient = new TableClient(driver, new TableClientConfig());
    _database = new NAuthAPI.AppContext(tableClient, names.Issuer);
}
else
{
    throw new Exception("Драйвер базы данных не запущен");
}

IKVEngine kvService;
if (!string.IsNullOrEmpty(lake_auth))
{
    var iam = File.ReadAllBytes(lake_auth);
    kvService = new KeyLakeService(new HttpClient(), kv_address, names.Issuer, "KeyLake", iam);
}
else if (!string.IsNullOrEmpty(vault_auth))
{
    kvService = new VaultService(kv_address, vault_auth);
}
else
{
    kvService = new InternalService();
}

builder.Services.AddControllers();
builder.Services.AddAuthentication(JwtBearerDefaults.AuthenticationScheme)
    .AddJwtBearer(JwtBearerDefaults.AuthenticationScheme,
        options => 
        {
            options.TokenValidationParameters = new TokenValidationParameters()
            {
                ValidateIssuer = true,
                ValidIssuer = names.Issuer,
                ValidateAudience = true,
                AudienceValidator = (aud, das, vvb) => {
                    int count = 0;
                    int valid = 0;
                    foreach(var a in aud)
                    {
                        count++;
                        Client? client = _database.GetClient(a).Result;
                        if (client != null)
                        {
                            if (client.IsValid) valid++;
                        }
                    }
                    return valid == count;
                },
                ValidateLifetime = true,
                ValidateIssuerSigningKey = true,
                IssuerSigningKeyValidator = (key, token, param) => {
                    return _database.IsKeyValid(key.KeyId).Result;
                },
                IssuerSigningKeyResolver = (token, secToken, kid, param) => {
                    var list = new List<SecurityKey>();
                    try
                    {
                        var payload = kvService.GetKey(kid);
                        var key = new SymmetricSecurityKey(Convert.FromBase64String(payload))
                        {
                            KeyId = kid
                        };
                        list.Add(key);
                    }
                    catch (Exception) { }
                    return list;
                }
            };
        });
builder.Services.AddAuthorization();
builder.Services.AddHttpClient();
builder.Services.AddSingleton(_database);
builder.Services.AddSingleton(kvService);
builder.Services.AddSingleton(names);

var app = builder.Build();

app.UseHttpsRedirection();

app.UseAuthentication();
app.UseAuthorization();

app.UseClientMiddleware();

app.MapControllers();

app.Run();
