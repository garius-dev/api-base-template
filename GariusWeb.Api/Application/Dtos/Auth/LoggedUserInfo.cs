using System.Security.Claims;

namespace GariusWeb.Api.Application.Dtos.Auth
{
    public class LoggedUserInfo
    {
        public Guid UserId { get; set; }
        public string Email { get; set; } = string.Empty;
        public string Name { get; set; } = string.Empty;
        public Guid TenantId { get; set; }
        public string TenantName { get; set; } = string.Empty;
        public IEnumerable<string?> Roles { get; set; } = new List<string>();
        public IEnumerable<LoggedUserClaims> Claims { get; set; } = new List<LoggedUserClaims>();
        public int TopRoleLevel { get; set; } = 999;
    }

    public class LoggedUserClaims
    {
        public string? ClaimType { get; set; }
        public string? ClaimValue { get; set; }
    }
}
