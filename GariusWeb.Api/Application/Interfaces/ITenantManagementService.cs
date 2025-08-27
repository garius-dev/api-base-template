using GariusWeb.Api.Application.Dtos.Tenants;

namespace GariusWeb.Api.Application.Interfaces
{
    public interface ITenantManagementService
    {
        Task<IEnumerable<TenantResponse>> GetAllTenantsAsync(CancellationToken cancellationToken = default);
        Task<TenantResponse> GetTenantByIdAsync(Guid id);
        Task<TenantResponse> CreateTenantAsync(CreateTenantRequest request, CancellationToken cancellationToken = default);
        Task<TenantResponse> UpdateTenantAsync(Guid id, UpdateTenantRequest request, CancellationToken cancellationToken = default);
        Task ActivateTenantAsync(Guid id, CancellationToken cancellationToken = default);
        Task DeactivateTenantAsync(Guid id, CancellationToken cancellationToken = default);
    }
}
