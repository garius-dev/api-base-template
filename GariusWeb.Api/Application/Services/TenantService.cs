using GariusWeb.Api.Application.Interfaces;
using GariusWeb.Api.Configuration;
using Microsoft.Extensions.Options;

namespace GariusWeb.Api.Application.Services
{
    public class TenantService : ITenantService
    {
        private readonly IHttpContextAccessor _httpContextAccessor;
        private readonly Guid _defaultTenantId;

        public TenantService(IHttpContextAccessor httpContextAccessor, IOptions<AppSecretsConfiguration.TenantSettings> tenantSettings)
        {
            _httpContextAccessor = httpContextAccessor;
            if (tenantSettings.Value.Mode == AppSecretsConfiguration.TenantMode.Dedicated)
            {
                _defaultTenantId = tenantSettings.Value.DefaultTenantId;
            }
        }

        public Guid GetTenantId()
        {
            var httpContext = _httpContextAccessor.HttpContext;

            if (httpContext?.Request.Headers.TryGetValue("X-Tenant-Id", out var tenantIdHeader) == true &&
                Guid.TryParse(tenantIdHeader, out var tenantId))
            {
                return tenantId;
            }

            return _defaultTenantId;
        }
    }
}
