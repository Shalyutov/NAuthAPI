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
using Ydb.Sdk.Table;
using Ydb.Sdk.Yc;

var builder = WebApplication.CreateBuilder(args);

string keypath = builder.Configuration["KeyPath"] ?? "";
string endpoint = builder.Configuration["Endpoint"] ?? "";
string database = builder.Configuration["Database"] ?? "";
string issuer = builder.Configuration["Issuer"] ?? "";
string audience = builder.Configuration["Audience"] ?? "";
string lake = builder.Configuration["KeyLake"] ?? "";
string auth = builder.Configuration["Auth"] ?? "";

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
    provider = new AnonymousProvider();
}

for(int i = 0; i < 6; i++)//retry connect //переподключение
{
    try
    {
        var config = new DriverConfig(endpoint, database, provider);
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
    _database = new NAuthAPI.AppContext(tableClient, issuer);
}
else
{
    throw new Exception("Драйвер базы данных не запущен");
}

var LakeService = new KeyLakeService(new HttpClient(), lake, issuer, "KeyLake", auth);

builder.Services.AddControllers();
builder.Services.AddAuthentication(JwtBearerDefaults.AuthenticationScheme)
    .AddJwtBearer(JwtBearerDefaults.AuthenticationScheme,
        options => 
        {
            options.TokenValidationParameters = new TokenValidationParameters()
            {
                ValidateIssuer = true,
                ValidIssuer = issuer,
                ValidateAudience = true,
                ValidAudience = audience,
                ValidateLifetime = true,
                ValidateIssuerSigningKey = true,
                IssuerSigningKeyValidator = (key, token, param) => {
                    return _database.IsKeyValid(key.KeyId).Result;
                },
                IssuerSigningKeyResolver = (token, secToken, kid, param) => {
                    var list = new List<SecurityKey>();
                    try
                    {
                        var payload = LakeService.GetKey(kid).Result;
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
builder.Services.AddSingleton(LakeService);
builder.Configuration.AddEnvironmentVariables();

var app = builder.Build();

app.UseHttpsRedirection();

app.UseAuthentication();
app.UseAuthorization();

app.MapControllers();

app.Run();
