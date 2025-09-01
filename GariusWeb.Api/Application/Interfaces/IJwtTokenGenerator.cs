using GariusWeb.Api.Domain.Entities.Identity;
using GariusWeb.Api.Domain.Entities.ServiceAccount;
using System.Security.Claims;

namespace GariusWeb.Api.Application.Interfaces
{
    public interface IJwtTokenGenerator
    {
        Task<string> GenerateToken(ApplicationUser user, IList<string> roles);
        //string GenerateToken(ApplicationUser user, IEnumerable<string> roles);
        string GenerateServiceAccountToken(ServiceAccountEntity serviceAccount); // Adicionar este método
        ClaimsPrincipal GetPrincipalFromExpiredToken(string token);
    }
}