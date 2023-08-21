using Microsoft.AspNetCore.Authorization;
using Microsoft.AspNetCore.Builder;
using Microsoft.AspNetCore.Http;
using Microsoft.AspNetCore.Http.Features;
using Microsoft.AspNetCore.Mvc.Controllers;
using System.Linq;
using System.Threading.Tasks;

namespace NAuthAPI
{
    // You may need to install the Microsoft.AspNetCore.Http.Abstractions package into your project
    public class ClientMiddleware
    {
        private readonly RequestDelegate _next;

        public ClientMiddleware(RequestDelegate next)
        {
            _next = next;
        }

        public async Task InvokeAsync(HttpContext httpContext, AppContext database)
        {
            var endpoint = httpContext
                ?.GetEndpoint()
                ?.Metadata
                ?.GetMetadata<ControllerActionDescriptor>();
            object[] attributes = endpoint?.MethodInfo?.GetCustomAttributes(false) ?? Array.Empty<object>();
            foreach (var item in attributes)
            {
                if (item as TrustClientAttribute != null)
                {
                    string client = httpContext!.Request.Headers["client"].First() ?? string.Empty;
                    string secret = httpContext!.Request.Headers["secret"].First() ?? string.Empty;
                    
                    Client? _client = await Client.GetClientAsync(database, client, secret);
                    if (_client != null)
                    {
                        if (_client.IsTrusted)
                        {
                            httpContext.Items.Add("client", _client);
                            break;
                        }
                        else
                        {
                            throw new Exception("Клиентское приложение должно иметь доверенную реализацию");
                        }
                    }
                    else
                    {
                        throw new Exception("Клиентское приложение должно быть авторизовано");
                    }
                }
                else if (item as ClientAttribute != null)
                {
                    string client = httpContext!.Request.Headers["client"].First() ?? string.Empty;
                    string secret = httpContext!.Request.Headers["secret"].First() ?? string.Empty;
                    Client? _client = await Client.GetClientAsync(database, client, secret);
                    if (_client == null)
                    {
                        throw new Exception("Клиентское приложение должно быть авторизовано");
                    }
                    else
                    {
                        httpContext.Items.Add("client", _client);
                        break;
                    }
                }
                else
                {
                    continue;
                }
            }
            await _next(httpContext!);
        }
    }

    // Extension method used to add the middleware to the HTTP request pipeline.
    public static class ClientMiddlewareExtensions
    {
        public static IApplicationBuilder UseClientMiddleware(this IApplicationBuilder builder)
        {
            return builder.UseMiddleware<ClientMiddleware>();
        }
    }
}
