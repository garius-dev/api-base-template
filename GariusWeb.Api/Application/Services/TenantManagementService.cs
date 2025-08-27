using AutoMapper;
using GariusWeb.Api.Application.Dtos.Tenants;
using GariusWeb.Api.Application.Exceptions;
using GariusWeb.Api.Application.Interfaces;
using GariusWeb.Api.Domain.Entities;
using GariusWeb.Api.Infrastructure.Data;
using Microsoft.EntityFrameworkCore;

namespace GariusWeb.Api.Application.Services
{
    public class TenantManagementService : ITenantManagementService
    {
        private readonly ApplicationDbContext _context;
        private readonly ILogger<TenantManagementService> _logger;
        private readonly MapperService _mapper;

        public TenantManagementService(ApplicationDbContext context, ILogger<TenantManagementService> logger, MapperService mapper)
        {
            _context = context;
            _logger = logger;
            _mapper = mapper;
        }

        public async Task<TenantResponse> CreateTenantAsync(CreateTenantRequest request, CancellationToken cancellationToken = default)
        {
            var existingTenant = await _context.Tenants
                .AsNoTracking()
                .FirstOrDefaultAsync(t => t.Name.ToUpper() == request.Name.ToUpper()).ConfigureAwait(false);

            if (existingTenant != null)
            {
                throw new ConflictException("Já existe um tenant com este nome.");
            }

            var newTenant = new Tenant
            {
                Name = request.Name,
                IsActive = true,
                CreatedAt = DateTime.UtcNow
            };

            _context.Tenants.Add(newTenant);
            await _context.SaveChangesAsync(cancellationToken).ConfigureAwait(false);

            _logger.LogInformation("Novo tenant criado: {TenantName} (ID: {TenantId})", newTenant.Name, newTenant.Id);

            return _mapper.Map<Tenant, TenantResponse>(newTenant);
        }

        public async Task<IEnumerable<TenantResponse>> GetAllTenantsAsync(CancellationToken cancellationToken = default)
        {
            var tenants = await _context.Tenants.AsNoTracking().ToListAsync(cancellationToken).ConfigureAwait(false);

            return _mapper.MapList<Tenant, TenantResponse>(tenants);
        }

        public async Task<TenantResponse> GetTenantByIdAsync(Guid id)
        {
            var tenant = await FindTenantByIdAsync(id).ConfigureAwait(false);
            return _mapper.Map<Tenant, TenantResponse>(tenant);
        }

        public async Task<TenantResponse> UpdateTenantAsync(Guid id, UpdateTenantRequest request, CancellationToken cancellationToken = default)
        {
            var tenant = await FindTenantByIdAsync(id).ConfigureAwait(false);
            tenant.Name = request.Name;
            tenant.UpdatedAt = DateTime.UtcNow;
            tenant.IsDummy = request.IsDummy;

            await _context.SaveChangesAsync(cancellationToken).ConfigureAwait(false);
            _logger.LogInformation("Tenant atualizado: {TenantName} (ID: {TenantId})", tenant.Name, tenant.Id);

            return _mapper.Map<Tenant, TenantResponse>(tenant);
        }

        public async Task ActivateTenantAsync(Guid id, CancellationToken cancellationToken = default)
        {
            var tenant = await FindTenantByIdAsync(id).ConfigureAwait(false);
            if (tenant.IsActive) return; // Já está ativo

            tenant.IsActive = true;
            tenant.UpdatedAt = DateTime.UtcNow;
            await _context.SaveChangesAsync(cancellationToken).ConfigureAwait(false);
            _logger.LogInformation("Tenant ativado: {TenantName} (ID: {TenantId})", tenant.Name, tenant.Id);
        }

        public async Task DeactivateTenantAsync(Guid id, CancellationToken cancellationToken = default)
        {
            var tenant = await FindTenantByIdAsync(id).ConfigureAwait(false);
            if (!tenant.IsActive) return; // Já está inativo

            tenant.IsActive = false;
            tenant.UpdatedAt = DateTime.UtcNow;
            await _context.SaveChangesAsync(cancellationToken).ConfigureAwait(false);
            _logger.LogWarning("Tenant desativado: {TenantName} (ID: {TenantId})", tenant.Name, tenant.Id);
        }

        // --- Métodos Auxiliares ---
        private async Task<Tenant> FindTenantByIdAsync(Guid id)
        {
            var tenant = await _context.Tenants.FirstOrDefaultAsync(t => t.Id == id).ConfigureAwait(false);
            return tenant ?? throw new NotFoundException("Tenant");
        }
    }
}
