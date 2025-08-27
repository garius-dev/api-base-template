using GariusWeb.Api.Application.Dtos.SystemUsers;

namespace GariusWeb.Api.Application.Interfaces.SystemUsers
{
    public interface ISystemUserResolver
    {
        Task<SystemUser?> FindByEmailAsync(string email);
        Task<SystemUser?> FindByIdAsync(Guid userId);

        Task<SystemUser?> FindByEmailTrackedAsync(string email);
        Task<SystemUser?> FindByIdTrackedAsync(Guid userId);
    }
}
