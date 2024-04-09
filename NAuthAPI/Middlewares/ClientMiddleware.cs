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
    public class ClientMiddleware(RequestDelegate next)
    {
        private readonly RequestDelegate _next = next;

        public async Task InvokeAsync(HttpContext httpContext, IAppContext database)
        {
            var endpoint = httpContext
                ?.GetEndpoint()
                ?.Metadata
                ?.GetMetadata<ControllerActionDescriptor>();
            object[] attributes = endpoint?.MethodInfo?.GetCustomAttributes(false) ?? [];

            string? client = httpContext?.Request.Headers["client"].FirstOrDefault();
            string? secret = httpContext?.Request.Headers["secret"].FirstOrDefault();

            foreach (var item in attributes)
            {
                if (item as TrustClientAttribute != null)
                {
                    if (await ClientValidator.IsTrustedValidClient(database, client!, secret!))
                    {
                        httpContext?.Items.Add("client", client);
                        break;
                    }
                    else
                    {
                        throw new Exception("Ошибка доступа. Клиентское приложение с недоверенной реализацией.");
                    }
                }
                else if (item as ClientAttribute != null)
                {
                    if (await ClientValidator.IsValidClient(database, client!, secret!))
                    {
                        httpContext?.Items.Add("client", client);
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
