using Asp.Versioning;
using GariusWeb.Api.Application.Dtos.Roles;
using GariusWeb.Api.Application.Exceptions;
using GariusWeb.Api.Application.Interfaces;
using GariusWeb.Api.Domain.Constants;
using GariusWeb.Api.Extensions;
using GariusWeb.Api.Helpers;
using Microsoft.AspNetCore.Authorization;
using Microsoft.AspNetCore.Mvc;
using System.Security.Claims;

namespace GariusWeb.Api.WebApi.Controllers.v1
{
    [ApiController]
    [Route("api/v{version:apiVersion}/roles")]
    [ApiVersion("1.0")]
    public class RolesController : ControllerBase
    {
        private readonly IRoleService _roleService;

        public RolesController(IRoleService roleService)
        {
            _roleService = roleService;
        }

        [Authorize(Roles = "Developer,SuperAdmin,Owner,Admin")]
        [HttpGet]
        public async Task<IActionResult> GetRoles(CancellationToken cancellationToken = default)
        {
            IList<string> roles = await _roleService.GetRolesAsync(cancellationToken);

            return Ok(ApiResponse<IList<string>>.Ok(roles));
        }

        [Authorize(Roles = "Developer,SuperAdmin")]
        [HttpPost("create")]
        public async Task<IActionResult> CreateNewRole([FromBody] CreateRoleRequest request)
        {
            if (!ModelState.IsValid)
                throw new ValidationException("Requisição inválida: " + ModelState.ToFormattedErrorString());

            await _roleService.CreateRoleAsync(request);

            return Ok(ApiResponse<string>.Ok($"Role '{request.RoleName}' criada com sucesso"));
        }

        [Authorize(Roles = "Developer,SuperAdmin")]
        [HttpDelete("{roleName}")]
        public async Task<IActionResult> DeleteRole(string roleName)
        {
            await _roleService.RemoveRoleAsync(roleName);

            return Ok(ApiResponse<string>.Ok($"Role '{roleName}' deletada com sucesso"));
        }

        [Authorize(Roles = "Developer,SuperAdmin")]
        [HttpPatch("{roleName}")]
        public async Task<IActionResult> UpdateRole(string roleName, [FromBody] UpdateRoleRequest request)
        {
            if (!ModelState.IsValid)
                throw new ValidationException("Requisição inválida: " + ModelState.ToFormattedErrorString());

            await _roleService.UpdateRoleAsync(roleName, request);

            return Ok(ApiResponse<string>.Ok($"Role '{roleName}' atualizada com sucesso"));
        }

        
    }
}