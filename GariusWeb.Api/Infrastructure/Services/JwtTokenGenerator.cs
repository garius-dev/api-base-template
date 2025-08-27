using GariusWeb.Api.Application.Interfaces;
using GariusWeb.Api.Configuration;
using GariusWeb.Api.Domain.Entities.Identity;
using GariusWeb.Api.Domain.Entities.ServiceAccount;
using Microsoft.Extensions.Options;
using Microsoft.IdentityModel.Tokens;
using System.IdentityModel.Tokens.Jwt;
using System.Security.Claims;
using System.Text;

namespace GariusWeb.Api.Infrastructure.Services
{
    public class JwtTokenGenerator : IJwtTokenGenerator
    {
        private readonly AppSecrets.JwtSettings _jwtSettings;

        public JwtTokenGenerator(IOptions<AppSecrets.JwtSettings> jwtSettings)
        {
            _jwtSettings = jwtSettings.Value;
        }

        public string GenerateToken(ApplicationUser user, IList<string> roles, IList<Claim>? additionalClaims = null)
        {
            var claims = new List<Claim>
            {
                new(JwtRegisteredClaimNames.Sub, user.Id.ToString()),
                new(JwtRegisteredClaimNames.Email, user.Email!),
                new(ClaimTypes.Name, user.UserName ?? user.Email ?? user.Id.ToString()),
                new("firstName", user.FirstName ?? string.Empty),
                new("lastName", user.LastName ?? string.Empty),
                new("tenantId", user.TenantId.ToString()),
            };

            // Adiciona roles
            var selectedRoles = roles.Select(role => new Claim(ClaimTypes.Role, role));
            claims.AddRange(selectedRoles);

            // Adiciona claims personalizadas, se houver
            if (additionalClaims != null)
            {
                claims.AddRange(additionalClaims);
            }

            var key = new SymmetricSecurityKey(Encoding.UTF8.GetBytes(_jwtSettings.Secret));
            var creds = new SigningCredentials(key, SecurityAlgorithms.HmacSha256);

            var token = new JwtSecurityToken(
                issuer: _jwtSettings.Issuer,
                audience: _jwtSettings.Audience,
                claims: claims,
                expires: DateTime.UtcNow.AddMinutes(_jwtSettings.ExpirationInMinutes),
                signingCredentials: creds
            );

            return new JwtSecurityTokenHandler().WriteToken(token);
        }

        public string GenerateServiceAccountToken(ServiceAccountEntity serviceAccount)
        {
            var claims = new List<Claim>
            {
                new(JwtRegisteredClaimNames.Jti, Guid.NewGuid().ToString()),
                new(JwtRegisteredClaimNames.Sub, serviceAccount.ClientId),
                new("partner", serviceAccount.PartnerName),
            };

            // Adiciona os scopes como claims separadas
            foreach (var scope in serviceAccount.Scopes)
            {
                claims.Add(new Claim("scope", scope));
            }

            var key = new SymmetricSecurityKey(Encoding.UTF8.GetBytes(_jwtSettings.Secret));
            var creds = new SigningCredentials(key, SecurityAlgorithms.HmacSha256);

            var token = new JwtSecurityToken(
                issuer: _jwtSettings.Issuer,
                audience: _jwtSettings.Audience,
                claims: claims,
                expires: DateTime.UtcNow.AddHours(1), // Expiração curta!
                signingCredentials: creds
            );

            return new JwtSecurityTokenHandler().WriteToken(token);
        }

        public ClaimsPrincipal GetPrincipalFromExpiredToken(string token)
        {
            var tokenValidationParameters = new TokenValidationParameters
            {
                ValidateAudience = true,
                ValidateIssuer = true,
                ValidateIssuerSigningKey = true,
                IssuerSigningKey = new SymmetricSecurityKey(Encoding.UTF8.GetBytes(_jwtSettings.Secret)),
                ValidateLifetime = false, // Chave da implementação: não valida o tempo de expiração
                ValidIssuer = _jwtSettings.Issuer,
                ValidAudience = _jwtSettings.Audience,
                ClockSkew = TimeSpan.Zero
            };

            var tokenHandler = new JwtSecurityTokenHandler();
            var principal = tokenHandler.ValidateToken(token, tokenValidationParameters, out var securityToken);

            if (securityToken is not JwtSecurityToken jwtSecurityToken ||
                !jwtSecurityToken.Header.Alg.Equals(SecurityAlgorithms.HmacSha256, StringComparison.InvariantCultureIgnoreCase))
            {
                throw new SecurityTokenException("Token inválido.");
            }

            return principal;
        }
    }
}
