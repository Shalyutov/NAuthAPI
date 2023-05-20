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

ICredentialsProvider provider;

if (keypath != "")//Используем авторизованный ключ доступа если он задан в настройках приложения
{
    provider = new ServiceAccountProvider(keypath);
    ((ServiceAccountProvider)provider).Initialize().Wait();
}
else
{
    provider = new AnonymousProvider();
}

var config = new DriverConfig(endpoint, database, provider);
var driver = new Driver(config);
driver.Initialize().Wait();

var TableClient = new TableClient(driver, new TableClientConfig());
var Database = new NAuthAPI.AppContext(TableClient, issuer);

builder.Services.AddControllers();
builder.Services.AddAuthentication(JwtBearerDefaults.AuthenticationScheme)
    .AddJwtBearer(JwtBearerDefaults.AuthenticationScheme,
        options => 
        {
            options.TokenValidationParameters = new Microsoft.IdentityModel.Tokens.TokenValidationParameters()
            {
                ValidateIssuer = true,
                ValidIssuer = issuer,
                ValidateAudience = true,
                ValidAudience = audience,
                ValidateLifetime = true,
                IssuerSigningKeyValidator = (key, token, param) => {
                    return Database.IsKeyValid(key.KeyId).Result;
                },
                IssuerSigningKeyResolver = (token, secToken, kid, param) => {
                    var list = new List<SecurityKey>();
                    try
                    {
                        var keystr = File.ReadAllText($"keys/{kid}.key");
                        var key = new SymmetricSecurityKey(Convert.FromBase64String(keystr))
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
builder.Services.AddSingleton(Database);
builder.Configuration.AddEnvironmentVariables();

var app = builder.Build();

app.UseHttpsRedirection();

app.UseAuthentication();
app.UseAuthorization();

app.MapControllers();

app.Run();
