using AngleSharp.Css;
using GariusWeb.Api.Application.Dtos.Accounts;
using GariusWeb.Api.Application.Dtos.Auth;
using GariusWeb.Api.Application.Dtos.Roles;
using GariusWeb.Api.Application.Exceptions;
using GariusWeb.Api.Application.Interfaces;
using GariusWeb.Api.Application.Interfaces.SystemUsers;
using GariusWeb.Api.Domain.Entities.Identity;
using GariusWeb.Api.Helpers;
using Microsoft.AspNetCore.Identity;
using Microsoft.EntityFrameworkCore;
using StackExchange.Redis;
using System.Security.Claims;

namespace GariusWeb.Api.Application.Services
{
    public class RoleService : IRoleService
    {
        private readonly RoleManager<ApplicationRole> _roleManager;
        private readonly UserManager<ApplicationUser> _userManager;
        private readonly LoggedUserHelper _loggedUserHelper;
        private readonly ILogger<RoleService> _logger;
        private readonly ISystemUserResolver _systemUserResolver;

        public RoleService(
            RoleManager<ApplicationRole> roleManager,
            UserManager<ApplicationUser> userManager,
            LoggedUserHelper loggedUserHelper,
            ISystemUserResolver systemUserResolver,
            ILogger<RoleService> logger)
        {
            _roleManager = roleManager;
            _userManager = userManager;
            _loggedUserHelper = loggedUserHelper;
            _logger = logger;
            _systemUserResolver = systemUserResolver;
        }

        
        public async Task CreateRoleAsync(CreateRoleRequest request)
        {
            if (request is null)
                throw new BadRequestException("Requisição inválida.");

            var roleName = NormalizeRoleName(request.RoleName);
            var loggedUserInfo = await _loggedUserHelper.GetLoggedUserInfoAsync().ConfigureAwait(false);

            EnsureCanCreateOrAssignRole(loggedUserInfo.TopRoleLevel, request.RoleLevel);

            var roleExists = await _roleManager.RoleExistsAsync(roleName).ConfigureAwait(false);
            if (roleExists)
                throw new ConflictException($"A role '{roleName}' já existe.");

            var role = new ApplicationRole(roleName, description: null, request.RoleLevel);
            var result = await _roleManager.CreateAsync(role).ConfigureAwait(false);

            if (!result.Succeeded)
                throw new InternalServerErrorAppException("Erro ao criar a role: " + GetErrors(result));

            foreach (var permission in request.Permissions.Distinct())
            {
                await _roleManager.AddClaimAsync(role, new Claim("permission", permission));
            }

            _logger.LogInformation("Role {RoleName} (Level {Level}) criada por UserId {UserId}.",
                roleName, request.RoleLevel, loggedUserInfo.UserId.ToString());
        }

        public async Task<IList<string>> GetRolesAsync(CancellationToken cancellationToken = default)
        {
            var loggedUserInfo = await _loggedUserHelper.GetLoggedUserInfoAsync().ConfigureAwait(false);

            return await _roleManager.Roles
                .AsNoTracking()
                .Where(r => r.Level >= loggedUserInfo.TopRoleLevel)
                .OrderBy(r => r.Level).ThenBy(r => r.Name)
                .Select(r => r.Name!)
                .ToListAsync(cancellationToken).ConfigureAwait(false);
        }

        public async Task UpdateRoleAsync(string roleName, UpdateRoleRequest request)
        {
            ApplicationRole? role = await _roleManager.FindByNameAsync(roleName).ConfigureAwait(false);

            if (role == null)
                throw new NotFoundException($"Role '{roleName}' não encontrada.");

            var loggedUserInfo = await _loggedUserHelper.GetLoggedUserInfoAsync().ConfigureAwait(false);

            EnsureCanManageRole(loggedUserInfo.TopRoleLevel, role.Level);

            bool hasChanges = false;
            if (!string.IsNullOrWhiteSpace(request.RoleName) && role.Name != request.RoleName)
            {
                var existingRoleWithNewName = await _roleManager.FindByNameAsync(request.RoleName).ConfigureAwait(false);
                if (existingRoleWithNewName != null)
                {
                    throw new ConflictException($"A role '{request.RoleName}' já existe.");
                }

                role.Name = request.RoleName;
                role.NormalizedName = _roleManager.NormalizeKey(request.RoleName);
                hasChanges = true;
            }

            if (request.RoleLevel.HasValue && role.Level != request.RoleLevel.Value)
            {
                role.Level = request.RoleLevel.Value;
                hasChanges = true;
            }

            if (hasChanges)
            {
                var result = await _roleManager.UpdateAsync(role).ConfigureAwait(false);

                if (!result.Succeeded)
                    throw new InternalServerErrorAppException("Erro ao atualizar a role: " + GetErrors(result));

                if (request.Permissions != null && request.Permissions.Any())
                {
                    var currentClaims = await _roleManager.GetClaimsAsync(role);
                    var currentPermissionClaims = currentClaims.Where(c => c.Type == "permission").ToList();
                    var requestedPermissions = request.Permissions.Distinct().ToList();

                    var claimsToRemove = currentPermissionClaims.Where(c => !requestedPermissions.Contains(c.Value)).ToList();
                    foreach (var claim in claimsToRemove)
                    {
                        await _roleManager.RemoveClaimAsync(role, claim);
                    }

                    var newPermissions = requestedPermissions.Where(p => !currentPermissionClaims.Any(c => c.Value == p)).ToList();
                    foreach (var permission in newPermissions)
                    {
                        await _roleManager.AddClaimAsync(role, new Claim("permission", permission));
                    }
                }                    
            }
        }

        public async Task RemoveRoleAsync(string roleName)
        {
            ApplicationRole? role = await _roleManager.FindByNameAsync(roleName).ConfigureAwait(false);

            if (role == null)
                throw new NotFoundException($"Role '{roleName}' não encontrada.");

            var loggedUserInfo = await _loggedUserHelper.GetLoggedUserInfoAsync().ConfigureAwait(false);

            EnsureCanManageRole(loggedUserInfo.TopRoleLevel, role.Level);

            var result = await _roleManager.DeleteAsync(role).ConfigureAwait(false);

            if (!result.Succeeded)
                throw new InternalServerErrorAppException("Erro ao deletar a role: " + GetErrors(result));
        }

        public async Task<IList<string>> GetUserRolesAsync(string userEmail, CancellationToken cancellationToken = default)
        {
            var loggedUserInfo = await _loggedUserHelper.GetLoggedUserInfoAsync().ConfigureAwait(false);
            var targetUserDetails = await _systemUserResolver.FindByEmailAsync(userEmail).ConfigureAwait(false);

            if (targetUserDetails == null)
                throw new NotFoundException($"Usuário com e-mail '{userEmail}' não encontrado.");

            EnsureCanViewOrManageUser(loggedUserInfo.TopRoleLevel, targetUserDetails.TopRoleLevel);

            return targetUserDetails.Roles!;
        }

        public async Task AddRoleToUserAsync(Guid userId, UserRoleRequest request, CancellationToken cancellationToken = default)
        {
            if (request is null)
                throw new BadRequestException("Requisição inválida.");

            var loggedUserInfo = await _loggedUserHelper.GetLoggedUserInfoAsync().ConfigureAwait(false);
            var targetUserDetails = await _systemUserResolver.FindByIdTrackedAsync(userId).ConfigureAwait(false);

            if(targetUserDetails == null)
                throw new NotFoundException($"Usuário não encontrado.");

            if(targetUserDetails.TrackedUser == null)
                throw new NotFoundException($"Usuário não encontrado.");

            if (targetUserDetails.Roles.Any())
                throw new ConflictException("Usuário já possui uma role. Utilize a rota de atualização.");

            var roleToAdd = await FindRoleByNameAsync(request.RoleName).ConfigureAwait(false);

            EnsureCanCreateOrAssignRole(loggedUserInfo.TopRoleLevel, roleToAdd.Level);

            var result = await _userManager.AddToRoleAsync(targetUserDetails.TrackedUser, roleToAdd.Name!).ConfigureAwait(false);
            if (!result.Succeeded)
                throw new InternalServerErrorAppException("Erro ao adicionar role ao usuário: " + GetErrors(result));

            _logger.LogInformation("Role {RoleName} atribuída ao usuário {TargetUserId} por UserId {UserId}.",
                roleToAdd.Name, targetUserDetails.UserId, loggedUserInfo.UserId);
        }

        public async Task UpdateUserRoleAsync(Guid userId, UserRoleRequest request, CancellationToken cancellationToken = default)
        {
            if (request is null)
                throw new BadRequestException("Requisição inválida.");

            var loggedUserInfo = await _loggedUserHelper.GetLoggedUserInfoAsync().ConfigureAwait(false);
            var targetUserDetails = await _systemUserResolver.FindByIdTrackedAsync(userId).ConfigureAwait(false);

            if(targetUserDetails == null)
                throw new NotFoundException($"Usuário não encontrado.");

            if(targetUserDetails.TrackedUser == null)
                throw new NotFoundException($"Usuário não encontrado.");

            EnsureCanViewOrManageUser(loggedUserInfo.TopRoleLevel, targetUserDetails.TopRoleLevel);

            var newRole = await FindRoleByNameAsync(request.RoleName).ConfigureAwait(false);

            EnsureCanCreateOrAssignRole(loggedUserInfo.TopRoleLevel, newRole.Level);

            if (targetUserDetails.Roles.Contains(newRole.Name!, StringComparer.Ordinal))
                throw new ConflictException("O usuário já possui esta role.");

            var removeResult = await _userManager.RemoveFromRolesAsync(targetUserDetails.TrackedUser, targetUserDetails.Roles!).ConfigureAwait(false);
            if (!removeResult.Succeeded)
                throw new InternalServerErrorAppException("Erro ao remover roles antigas: " + GetErrors(removeResult));

            var addResult = await _userManager.AddToRoleAsync(targetUserDetails.TrackedUser, newRole.Name!).ConfigureAwait(false);
            if (!addResult.Succeeded)
                throw new InternalServerErrorAppException("Erro ao adicionar a nova role: " + GetErrors(addResult));

            _logger.LogInformation("Roles do usuário {TargetUserId} foram atualizadas para {RoleName} por UserId {UserId}.",
                targetUserDetails.UserId, newRole.Name, loggedUserInfo.UserId);
        }

        public async Task RemoveAllRolesFromUserAsync(UserEmailRequest request, CancellationToken cancellationToken = default)
        {
            if (request is null)
                throw new BadRequestException("Requisição inválida.");

            var loggedUserInfo = await _loggedUserHelper.GetLoggedUserInfoAsync().ConfigureAwait(false);
            var targetUserDetails = await _systemUserResolver.FindByEmailTrackedAsync(request.Email).ConfigureAwait(false);

            if(targetUserDetails == null)
                throw new NotFoundException($"Usuário não encontrado.");

            if(targetUserDetails.TrackedUser == null)
                throw new NotFoundException($"Usuário não encontrado.");

            if (!targetUserDetails.Roles.Any()) return;

            EnsureCanViewOrManageUser(loggedUserInfo.TopRoleLevel, targetUserDetails.TopRoleLevel);

            var result = await _userManager.RemoveFromRolesAsync(targetUserDetails.TrackedUser, targetUserDetails.Roles!).ConfigureAwait(false);
            if (!result.Succeeded)
                throw new InternalServerErrorAppException("Erro ao remover as roles do usuário: " + GetErrors(result));

            _logger.LogInformation("Todas as roles removidas do usuário {TargetUserId} por UserId {UserId}.",
                targetUserDetails.UserId, loggedUserInfo.UserId);
        }


        //HELPERS

        private static string NormalizeRoleName(string roleName) =>
            (roleName ?? string.Empty).Trim();

        private static void EnsureCanCreateOrAssignRole(int loggedTopLevel, int targetRoleLevel)
        {
            if (targetRoleLevel < loggedTopLevel)
                throw new ForbiddenAccessException("Você não tem permissão para criar/atribuir uma role superior à sua.");
        }

        private static void EnsureCanViewOrManageUser(int loggedTopLevel, int targetTopLevel)
        {
            if (loggedTopLevel >= targetTopLevel)
                throw new ForbiddenAccessException("Você não tem permissão para visualizar/gerenciar este usuário.");
        }

        private static void EnsureCanManageRole(int loggedTopLevel, int targetTopLevel)
        {
            if (loggedTopLevel >= targetTopLevel)
                throw new ForbiddenAccessException("Você não tem permissão para visualizar/gerenciar esta role.");
        }

        

        private async Task<ApplicationRole> FindRoleByNameAsync(string roleName)
        {
            var normalizedRoleName = NormalizeRoleName(roleName);
            var role = await _roleManager.FindByNameAsync(normalizedRoleName).ConfigureAwait(false);
            if (role != null)
                return role;
            throw new NotFoundException($"Role '{normalizedRoleName}' não encontrada.");
        }

        private static string GetErrors(IdentityResult result)
        {
            return string.Join("; ", result.Errors.Select(e => e.Description));
        }
    }
}