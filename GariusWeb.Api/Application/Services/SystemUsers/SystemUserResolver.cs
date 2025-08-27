using GariusWeb.Api.Application.Dtos.SystemUsers;
using GariusWeb.Api.Application.Interfaces.SystemUsers;
using GariusWeb.Api.Domain.Entities.Identity;
using Microsoft.AspNetCore.Identity;
using Microsoft.EntityFrameworkCore;
using System.Linq.Expressions;
using System.Security.Claims;

namespace GariusWeb.Api.Application.Services.SystemUsers
{
    public class SystemUserResolver : ISystemUserResolver
    {
        private readonly UserManager<ApplicationUser> _userManager;

        public SystemUserResolver(UserManager<ApplicationUser> userManager)
        {
            _userManager = userManager;
        }

        private IQueryable<ApplicationUser> BaseNoTrackingQuery()
        {
            return _userManager.Users
                .AsNoTracking()
                .Include(u => u.Tenant)
                .Include(ur => ur.UserRoles)
                    .ThenInclude(r => r.Role)
                .Include(c => c.Claims);
        }

        private IQueryable<ApplicationUser> BaseTrackingQuery()
        {
            return _userManager.Users
                .Include(u => u.Tenant)
                .Include(ur => ur.UserRoles)
                    .ThenInclude(r => r.Role)
                .Include(c => c.Claims);
        }

        private async Task<SystemUser?> FindNoTrackingAsync(Expression<Func<ApplicationUser, bool>> predicate)
        {
            return await BaseNoTrackingQuery()
                .Where(predicate)
                .Select(s => new SystemUser
                {
                    UserId = s.Id,
                    TenantId = s.TenantId,
                    Email = s.Email!,
                    Name = s.FullName,
                    TenantName = s.Tenant.Name,
                    Roles = s.UserRoles.Select(ur => ur.Role.Name).ToList(),
                    TopRoleLevel = s.UserRoles.Select(ur => (int?)ur.Role.Level).Min() ?? 999,
                    Claims = s.Claims
                        .Select(c => new Claim(c.ClaimType ?? string.Empty, c.ClaimValue ?? string.Empty))
                        .ToList()
                })
                .FirstOrDefaultAsync();
        }

        private async Task<SystemUser?> FindTrackingAsync(Expression<Func<ApplicationUser, bool>> predicate)
        {
            return await BaseTrackingQuery()
                .Where(predicate)
                .Select(s => new SystemUser
                {
                    TrackedUser = s,
                    UserId = s.Id,
                    TenantId = s.TenantId,
                    Email = s.Email!,
                    Name = s.FullName,
                    TenantName = s.Tenant.Name,
                    Roles = s.UserRoles.Select(ur => ur.Role.Name).ToList(),
                    TopRoleLevel = s.UserRoles.Select(ur => (int?)ur.Role.Level).Min() ?? 999,
                    Claims = s.Claims
                        .Select(c => new Claim(c.ClaimType ?? string.Empty, c.ClaimValue ?? string.Empty))
                        .ToList()
                })
                .FirstOrDefaultAsync();
        }

        public Task<SystemUser?> FindByEmailAsync(string email)
        {
            var normalizedEmail = _userManager.NormalizeEmail(email);
            return FindNoTrackingAsync(u => u.NormalizedEmail == normalizedEmail);
        }

        public Task<SystemUser?> FindByIdAsync(Guid userId)
        {
            return FindNoTrackingAsync(u => u.Id == userId);
        }

        public Task<SystemUser?> FindByEmailTrackedAsync(string email)
        {
            var normalizedEmail = _userManager.NormalizeEmail(email);
            return FindTrackingAsync(u => u.NormalizedEmail == normalizedEmail);
        }

        public Task<SystemUser?> FindByIdTrackedAsync(Guid userId)
        {
            return FindTrackingAsync(u => u.Id == userId);
        }
    }
}
