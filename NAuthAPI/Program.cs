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
using Ydb.Sdk.Table;
using Ydb.Sdk.Yc;

var builder = WebApplication.CreateBuilder(args);

var account = new ServiceAccountProvider("yandexSA.json");//авторизованный ключ доступа
account.Initialize().Wait();

var Config = new DriverConfig(
        endpoint: builder.Configuration["Endpoint"] ?? "",
        database: builder.Configuration["Database"] ?? "",
        credentials: account
        );
var Driver = new Driver(Config);
Driver.Initialize().Wait();

var TableClient = new TableClient(Driver, new TableClientConfig());
var Database = new YdbContext(TableClient);

builder.Services.AddControllers();
builder.Services.AddAuthentication(JwtBearerDefaults.AuthenticationScheme)
    .AddJwtBearer(JwtBearerDefaults.AuthenticationScheme,
        options => 
        {
            options.TokenValidationParameters = new Microsoft.IdentityModel.Tokens.TokenValidationParameters()
            {
                ValidateIssuer = true,
                ValidIssuer = AuthProperties.ISSUER,
                ValidateAudience = true,
                ValidAudience = AuthProperties.AUDIENCE,
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
