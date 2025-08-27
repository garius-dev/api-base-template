using Asp.Versioning;
using GariusWeb.Api.Application.Dtos.Accounts;
using GariusWeb.Api.Application.Exceptions;
using GariusWeb.Api.Application.Interfaces;
using GariusWeb.Api.Domain.Abstractions;
using GariusWeb.Api.Domain.Constants;
using GariusWeb.Api.Extensions;
using GariusWeb.Api.Helpers;
using Microsoft.AspNetCore.Authorization;
using Microsoft.AspNetCore.Mvc;
using System.Security.Claims;

namespace GariusWeb.Api.WebApi.Controllers.v1
{
    [ApiController]
    [Route("api/v{version:apiVersion}/accounts")]
    [ApiVersion("1.0")]
    public class AccountsController : ControllerBase
    {
        private readonly IUserService _userService;
        private readonly IRoleService _roleService;

        public AccountsController(IUserService userService, IRoleService roleService)
        {
            _userService = userService;
            _roleService = roleService;
        }

        [Authorize(Roles = "Developer,SuperAdmin,Owner,Admin")]
        [HttpGet("search")]
        public async Task<IActionResult> SearchAccounts(
            [FromQuery] string? searchTerm,
            [FromQuery] int pageSize = 10,
            [FromQuery] float? lastRank = null,
            [FromQuery] Guid? lastKey = null,
            CancellationToken cancellationToken = default)
        {
            var cursor = lastRank.HasValue || lastKey.HasValue
                ? new SearchCursor<Guid>(lastRank, lastKey)
                : (SearchCursor<Guid>?)null;

            var result = await _userService.SearchUsersAsync(searchTerm, pageSize, cursor: cursor, cancellationToken: cancellationToken);

            return Ok(ApiResponse<object>.Ok(result));
        }

        [Authorize(Roles = "Developer,SuperAdmin,Owner,Admin")]
        [HttpPost("{accountId}/roles")]
        public async Task<IActionResult> AddRoleToUser(Guid accountId, [FromBody] UserRoleRequest request, CancellationToken cancellationToken = default)
        {
            if (!ModelState.IsValid)
                throw new ValidationException("Requisição inválida: " + ModelState.ToFormattedErrorString());

            await _roleService.AddRoleToUserAsync(accountId, request, cancellationToken);

            return Ok(ApiResponse<string>.Ok($"Role '{request.RoleName}' vinculada ao usuário com sucesso"));
        }

        [Authorize(Roles = "Developer,SuperAdmin,Owner,Admin")]
        [HttpPut("{accountId}/roles")]
        public async Task<IActionResult> UpdateRoleFromUser(Guid accountId, [FromBody] UserRoleRequest request, CancellationToken cancellationToken = default)
        {
            if (!ModelState.IsValid)
                throw new ValidationException("Requisição inválida: " + ModelState.ToFormattedErrorString());

            await _roleService.UpdateUserRoleAsync(accountId, request, cancellationToken);

            return Ok(ApiResponse<string>.Ok($"Role '{request.RoleName}' do usuário alterada com sucesso"));
        }

        
    }
}