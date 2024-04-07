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

string? key = builder.Configuration["AuthKey"];
string endpoint = builder.Configuration["Endpoint"] ?? throw new Exception("Настройки должны содержать эндпоинт базы данных");
string databasePath = builder.Configuration["Database"] ?? throw new Exception("Настройки должны содержать путь до базы данных");
string stage = builder.Environment.EnvironmentName;

AuthNames names = new()
{
    Issuer = builder.Configuration["Issuer"] ?? "NAuth API",
    Audience = builder.Configuration["Audience"] ?? "NAuth App"
};

string? vault_auth = builder.Configuration["VaultAuth"];
string? kv_address = builder.Configuration["KVAddress"];

ICredentialsProvider provider;
Driver? driver = null;
TableClient? tableClient = null;
NAuthAPI.AppContext? database = null;

if (!string.IsNullOrEmpty(key)) //Используем авторизованный ключ доступа если он задан
{
    provider = new ServiceAccountProvider(key);
    await ((ServiceAccountProvider)provider).Initialize();
}
else
{
    provider = new AnonymousProvider(); //анонимная аутентификация по умолчанию 
}

for(int i = 0; i < 10; i++) //переподключение
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
    database = new NAuthAPI.AppContext(tableClient, stage, databasePath);
}
else
{
    throw new Exception("Драйвер базы данных не запущен");
}

IKVEngine kvService;
if (!string.IsNullOrEmpty(vault_auth) && !string.IsNullOrEmpty(kv_address))
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
                        Client? client = database.GetClient(a).Result;
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
                    return database.IsKeyValid(key.KeyId).Result;
                },
                IssuerSigningKeyResolver = (token, secToken, kid, param) => {
                    var list = new List<SecurityKey>();
                    try
                    {
                        var payload = kvService.GetKey(kid);
                        var key = new SymmetricSecurityKey(payload)
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
builder.Services.AddSingleton(database);
builder.Services.AddSingleton(kvService);
builder.Services.AddSingleton(names);

var app = builder.Build();

app.UseHttpsRedirection();

app.UseAuthentication();
app.UseAuthorization();

app.UseClientMiddleware();

app.MapControllers();

app.Run();
