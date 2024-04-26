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
using Microsoft.Extensions.Diagnostics.HealthChecks;
using Ydb.Sdk.Services.Scheme;

var builder = WebApplication.CreateBuilder(args);
builder.Configuration.AddEnvironmentVariables();

string? key = builder.Configuration["AuthKey"];
string endpoint = builder.Configuration["Endpoint"] ?? throw new Exception("Настройки должны содержать эндпоинт базы данных");
string databasePath = builder.Configuration["Database"] ?? throw new Exception("Настройки должны содержать путь до базы данных");
string stage = builder.Environment.EnvironmentName;
string issuer = builder.Configuration["Issuer"] ?? "NAuth API";

string? vaultAuth = builder.Configuration["VaultAuth"];
string? vaultEndpoint = builder.Configuration["VaultEndpoint"];

ICredentialsProvider provider;
Driver? driver = null;
TableClient tableClient;
IAppContext database;

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
    //var schemeClient = new SchemeClient(driver); библиотека на данный момент не поддерживает полноценную работу с директориями
    //TODO Добавить функционал для проверки и создания необходимых директорий
    tableClient = new TableClient(driver, new TableClientConfig());
    database = new YDBAppContext(tableClient, stage, databasePath);
    var table = await tableClient.DescribeTable($"NAuth/{stage}/users");
    if (!table.Status.IsSuccess)
    {
        if (!await database.CreateTables())
        {
            throw new Exception("Невозможно создать таблицы");
        }
    }
}
else
{
    throw new Exception("Драйвер базы данных не запущен");
}

IKVEngine kvService;
if (!string.IsNullOrEmpty(vaultAuth) && !string.IsNullOrEmpty(vaultEndpoint))
{
    kvService = new VaultService(vaultEndpoint, vaultAuth);
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
                ValidIssuer = issuer,
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
builder.Services.AddHealthChecks()
    .AddTypeActivatedCheck<DatabaseHealthCheck>("Database", HealthStatus.Unhealthy, new object[] {database} );

var app = builder.Build();

app.UseHttpsRedirection();

app.UseAuthentication();
app.UseAuthorization();

app.UseClientMiddleware();

app.MapControllers();
app.MapHealthChecks("/health");

app.Run();
