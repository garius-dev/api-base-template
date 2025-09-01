using GariusWeb.Api.Domain.Constants;
using GariusWeb.Api.Domain.Entities.Identity;
using Microsoft.AspNetCore.Identity;
using System.Security.Claims;

namespace GariusWeb.Api.Infrastructure.Data.Seed
{
    public static class ApplicationDbContextSeeder
    {
        public static async Task SeedRolesAndPermissionsAsync(IServiceProvider serviceProvider)
        {
            var roleManager = serviceProvider.GetRequiredService<RoleManager<ApplicationRole>>();
            var allPermissions = Permissions.GetAllPermissions();

            foreach (var roleName in SystemRoles.SuperUserRoles)
            {
                var role = await roleManager.FindByNameAsync(roleName);
                if (role == null)
                {
                    role = new ApplicationRole(roleName, $"{roleName} role with all permissions.", 0);
                    await roleManager.CreateAsync(role);
                }

                var currentClaims = await roleManager.GetClaimsAsync(role);
                var currentPermissions = currentClaims.Where(c => c.Type == "permission").Select(c => c.Value).ToHashSet();

                foreach (var permission in allPermissions)
                {
                    if (!currentPermissions.Contains(permission))
                    {
                        await roleManager.AddClaimAsync(role, new Claim("permission", permission));
                    }
                }
            }

            if (await roleManager.FindByNameAsync(SystemRoles.Basic) == null)
            {
                await roleManager.CreateAsync(new ApplicationRole(SystemRoles.Basic, "Basic user role with default permissions.", 10));
            }
        }
    }
}
