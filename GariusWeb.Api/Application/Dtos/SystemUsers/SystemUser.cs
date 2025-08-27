using GariusWeb.Api.Application.Interfaces.SystemUsers;
using GariusWeb.Api.Domain.Entities.Identity;
using System.Security.Claims;

namespace GariusWeb.Api.Application.Dtos.SystemUsers
{
    public class SystemUser : ISystemUser
    {
        public ApplicationUser? TrackedUser { get; set; } = null;

        public Guid UserId { get; set; }

        public string Email { get; set; } = string.Empty;

        public string Name { get; set; } = string.Empty;

        public Guid TenantId { get; set; }

        public string TenantName { get; set; } = string.Empty;

        public IList<string?> Roles { get; set; } = new List<string?>();

        public IList<Claim> Claims { get; set; } = new List<Claim>();

        public int TopRoleLevel { get; set; }
    }
}