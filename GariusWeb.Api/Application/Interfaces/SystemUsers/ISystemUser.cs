using GariusWeb.Api.Application.Dtos.Auth;
using System.Security.Claims;

namespace GariusWeb.Api.Application.Interfaces.SystemUsers
{
    public interface ISystemUser
    {
        Guid UserId { get; }
        string Email { get; }
        string Name { get; }
        Guid TenantId { get; }
        string TenantName { get; }
        IList<string?> Roles { get; }
        IList<Claim> Claims { get; }
        int TopRoleLevel { get; }
    }
}
