using GariusWeb.Api.Application.Dtos.Accounts;
using GariusWeb.Api.Application.Dtos.Auth;
using GariusWeb.Api.Application.Dtos.Roles;
using System.Security.Claims;

namespace GariusWeb.Api.Application.Interfaces
{
    public interface IRoleService
    {
        Task<IList<string>> GetRolesAsync(CancellationToken cancellationToken = default);

        Task<IList<string>> GetUserRolesAsync(string userEmail, CancellationToken cancellationToken = default);

        Task CreateRoleAsync(CreateRoleRequest request);

        Task RemoveRoleAsync(string roleName);

        Task UpdateRoleAsync(string roleName, UpdateRoleRequest request);

        Task AddRoleToUserAsync(Guid userId, UserRoleRequest request, CancellationToken cancellationToken = default);

        Task UpdateUserRoleAsync(Guid userId, UserRoleRequest request, CancellationToken cancellationToken = default);

        Task RemoveAllRolesFromUserAsync(UserEmailRequest request, CancellationToken cancellationToken = default);
                
    }
}