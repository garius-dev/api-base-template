using GariusWeb.Api.Application.Dtos.ServiceAccounts;
using GariusWeb.Api.Application.Exceptions;
using GariusWeb.Api.Application.Interfaces;
using GariusWeb.Api.Domain.Entities.ServiceAccount;
using GariusWeb.Api.Infrastructure.Data;
using Microsoft.AspNetCore.Identity;
using Microsoft.EntityFrameworkCore;
using System.Security.Cryptography;

namespace GariusWeb.Api.Application.Services
{
    public class ServiceAccountService : IServiceAccountService
    {
        private readonly ApplicationDbContext _context;
        private readonly IPasswordHasher<ServiceAccountEntity> _passwordHasher;

        public ServiceAccountService(ApplicationDbContext context, IPasswordHasher<ServiceAccountEntity> passwordHasher)
        {
            _context = context;
            _passwordHasher = passwordHasher;
        }

        public async Task<CreateServiceAccountResponse> CreateServiceAccountAsync(CreateServiceAccountRequest request)
        {
            var clientId = $"svc_{Guid.NewGuid():N}";
            var clientSecret = GenerateSecureRandomString(32);

            var serviceAccount = new ServiceAccountEntity
            {
                PartnerName = request.PartnerName,
                ClientId = clientId,
                Scopes = [.. request.Scopes],
                IsActive = true,
                CreatedAt = DateTime.UtcNow,
            };

            serviceAccount.HashedClientSecret = _passwordHasher.HashPassword(serviceAccount, clientSecret);

            await _context.ServiceAccounts.AddAsync(serviceAccount).ConfigureAwait(false);
            await _context.SaveChangesAsync().ConfigureAwait(false);

            return new CreateServiceAccountResponse
            {
                Id = serviceAccount.Id,
                PartnerName = serviceAccount.PartnerName,
                ClientId = serviceAccount.ClientId,
                ClientSecret = clientSecret, // Importante: retornar o segredo em texto plano apenas uma vez
                Scopes = [.. serviceAccount.Scopes],
            };
        }

        public async Task<ServiceAccountEntity?> ValidateCredentialsAsync(string clientId, string clientSecret)
        {
            var serviceAccount = await _context.ServiceAccounts
                .FirstOrDefaultAsync(sa => sa.ClientId == clientId).ConfigureAwait(false);

            if (serviceAccount?.IsActive != true)
            {
                return null;
            }

            var verificationResult = _passwordHasher.VerifyHashedPassword(serviceAccount, serviceAccount.HashedClientSecret, clientSecret);

            if (verificationResult == PasswordVerificationResult.Failed)
            {
                return null;
            }

            serviceAccount.UpdatedAt = DateTime.UtcNow;
            await _context.SaveChangesAsync().ConfigureAwait(false);

            return serviceAccount;
        }

        public async Task<IEnumerable<ServiceAccountDetailsDto>> GetAllServiceAccountsAsync()
        {
            return await _context.ServiceAccounts
                .AsNoTracking()
                .Select(sa => new ServiceAccountDetailsDto
                {
                    Id = sa.Id,
                    PartnerName = sa.PartnerName,
                    ClientId = sa.ClientId,
                    Scopes = sa.Scopes,
                    IsActive = sa.IsActive,
                    CreatedAt = sa.CreatedAt,
                    LastUsedAt = sa.UpdatedAt,
                })
                .ToListAsync().ConfigureAwait(false);
        }

        public async Task DeactivateServiceAccountAsync(Guid id)
        {
            var account = await _context.ServiceAccounts.FindAsync(id)
                .ConfigureAwait(false) ?? throw new NotFoundException($"Service Account com ID '{id}' não encontrado.");
            account.IsActive = false;
            await _context.SaveChangesAsync().ConfigureAwait(false);
        }

        public async Task ActivateServiceAccountAsync(Guid id)
        {
            var account = await _context.ServiceAccounts.FindAsync(id)
                .ConfigureAwait(false) ?? throw new NotFoundException($"Service Account com ID '{id}' não encontrado.");
            account.IsActive = true;
            await _context.SaveChangesAsync().ConfigureAwait(false);
        }

        private static string GenerateSecureRandomString(int length)
        {
            var bytes = new byte[length];
            using var rng = RandomNumberGenerator.Create();
            rng.GetBytes(bytes);
            return Convert.ToBase64String(bytes)
                .Replace("+", "-")
                .Replace("/", "_")
                .Substring(0, length);
        }
    }
}
