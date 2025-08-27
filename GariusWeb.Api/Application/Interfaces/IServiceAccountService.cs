using GariusWeb.Api.Application.Dtos.ServiceAccounts;
using GariusWeb.Api.Domain.Entities.ServiceAccount;

namespace GariusWeb.Api.Application.Interfaces
{
    public interface IServiceAccountService
    {
        Task<CreateServiceAccountResponse> CreateServiceAccountAsync(CreateServiceAccountRequest request);
        Task<ServiceAccountEntity?> ValidateCredentialsAsync(string clientId, string clientSecret);
        Task<IEnumerable<ServiceAccountDetailsDto>> GetAllServiceAccountsAsync();
        Task DeactivateServiceAccountAsync(Guid id);
        Task ActivateServiceAccountAsync(Guid id);
    }
}
