using Asp.Versioning;
using GariusWeb.Api.Application.Dtos.Tenants;
using GariusWeb.Api.Application.Interfaces;
using GariusWeb.Api.Helpers;
using Microsoft.AspNetCore.Authorization;
using Microsoft.AspNetCore.Mvc;

namespace GariusWeb.Api.WebApi.Controllers.v1
{
    [ApiController]
    [Route("api/v{version:apiVersion}/tenants")]
    [ApiVersion("1.0")]
    [Authorize(Roles = "SuperAdmin,Developer")]
    public class TenantsController : ControllerBase
    {
        private readonly ITenantManagementService _tenantService;

        public TenantsController(ITenantManagementService tenantService)
        {
            _tenantService = tenantService;
        }

        [HttpGet]
        public async Task<IActionResult> GetAll(CancellationToken cancellationToken = default)
        {
            var tenants = await _tenantService.GetAllTenantsAsync(cancellationToken);
            return Ok(ApiResponse<IEnumerable<TenantResponse>>.Ok(tenants));
        }

        [HttpGet("{id:guid}", Name = "GetTenantById")]
        public async Task<IActionResult> GetById(Guid id)
        {
            var tenant = await _tenantService.GetTenantByIdAsync(id);
            return Ok(ApiResponse<TenantResponse>.Ok(tenant));
        }

        [HttpPost]
        public async Task<IActionResult> Create([FromBody] CreateTenantRequest request, CancellationToken cancellationToken = default)
        {
            var newTenant = await _tenantService.CreateTenantAsync(request, cancellationToken);
            return CreatedAtAction(nameof(GetById), new { id = newTenant.Id }, ApiResponse<TenantResponse>.Ok(newTenant));
        }

        [HttpPut("{id:guid}")]
        public async Task<IActionResult> Update(Guid id, [FromBody] UpdateTenantRequest request, CancellationToken cancellationToken = default)
        {
            var updatedTenant = await _tenantService.UpdateTenantAsync(id, request, cancellationToken);
            return Ok(ApiResponse<TenantResponse>.Ok(updatedTenant));
        }

        [HttpPatch("{id:guid}/activate")]
        public async Task<IActionResult> Activate(Guid id, CancellationToken cancellationToken = default)
        {
            await _tenantService.ActivateTenantAsync(id, cancellationToken);
            return Ok(ApiResponse<TenantResponse>.Ok(null, "Tenant ativado com sucesso.")); // Sucesso, sem conteúdo para retornar
        }

        [HttpPatch("{id:guid}/deactivate")]
        public async Task<IActionResult> Deactivate(Guid id, CancellationToken cancellationToken = default)
        {
            await _tenantService.DeactivateTenantAsync(id, cancellationToken);
            return Ok(ApiResponse<TenantResponse>.Ok(null, "Tenant desativado com sucesso.")); // Sucesso, sem conteúdo para retornar
        }
    }
}