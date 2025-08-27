using GariusWeb.Api.Application.Dtos.Auth;
using GariusWeb.Api.Application.Interfaces.SystemUsers;

namespace GariusWeb.Api.Extensions
{
    public static class UserExtensions
    {
        public static bool HasRole(this ISystemUser user, string allowedRoles)
        {
            if (string.IsNullOrWhiteSpace(allowedRoles)) return false;

            var array = allowedRoles.Split(',')
                .Select(x => x.Trim())
                .ToArray();

            return array.Any(x => user.Roles.Contains(x, StringComparer.OrdinalIgnoreCase));
        }
    }
}
