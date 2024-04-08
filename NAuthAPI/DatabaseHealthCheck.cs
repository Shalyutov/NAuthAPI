using Microsoft.Extensions.Diagnostics.HealthChecks;
using System.Data.Common;
using System.Threading;

namespace NAuthAPI
{
    public class DatabaseHealthCheck(YDBAppContext db) : IHealthCheck
    {
        public Task<HealthCheckResult> CheckHealthAsync(HealthCheckContext context, CancellationToken cancellationToken = default)
        {
            bool isHealthy = db != null;
            if (isHealthy)
            {
                return Task.FromResult(HealthCheckResult.Healthy("Работает в штатном режиме"));
            }
            else
            {
                return Task.FromResult(new HealthCheckResult(context.Registration.FailureStatus, "Проблема с базой данных"));
            }
        }
    }
}
