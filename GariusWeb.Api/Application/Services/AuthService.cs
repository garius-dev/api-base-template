using GariusWeb.Api.Application.Dtos.Auth;
using GariusWeb.Api.Application.Dtos.Invitations;
using GariusWeb.Api.Application.Exceptions;
using GariusWeb.Api.Application.Interfaces;
using GariusWeb.Api.Domain.Constants;
using GariusWeb.Api.Domain.Entities;
using GariusWeb.Api.Domain.Entities.Identity;
using GariusWeb.Api.Domain.Interfaces;
using GariusWeb.Api.Extensions;
using GariusWeb.Api.Helpers;
using GariusWeb.Api.Infrastructure.Data;
using Microsoft.AspNetCore.Identity;
using Microsoft.AspNetCore.Mvc;
using Microsoft.AspNetCore.WebUtilities;
using Microsoft.EntityFrameworkCore;
using Microsoft.Extensions.Options;
using System.Data;
using System.Security.Claims;
using System.Security.Cryptography;
using static GariusWeb.Api.Configuration.AppSecrets;

namespace GariusWeb.Api.Application.Services
{
    public class AuthService : IAuthService
    {
        private readonly UserManager<ApplicationUser> _userManager;
        private readonly SignInManager<ApplicationUser> _signInManager;
        private readonly IJwtTokenGenerator _jwtTokenGenerator;
        private readonly ICacheService _cacheService;
        private readonly ITenantService _tenantService;

        private readonly ApplicationDbContext _dbContext;
        private readonly LoggedUserHelper _loggedUserHelper;

        private readonly UrlSettings _urlSettings;
        private readonly IServiceProvider _serviceProvider;

        public AuthService(UserManager<ApplicationUser> userManager,
                       IJwtTokenGenerator jwtTokenGenerator,
                       SignInManager<ApplicationUser> signInManager,
                       IOptions<UrlSettings> urlSettings,
                       ICacheService cacheService,
                       ITenantService tenantService,
                       LoggedUserHelper loggedUserHelper,
                       ApplicationDbContext dbContext,
                       IServiceProvider serviceProvider)
        {
            _userManager = userManager;
            _urlSettings = urlSettings.Value;
            _jwtTokenGenerator = jwtTokenGenerator;
            _signInManager = signInManager;
            _cacheService = cacheService;
            _tenantService = tenantService;
            _dbContext = dbContext;
            _loggedUserHelper = loggedUserHelper;
            _serviceProvider = serviceProvider;
        }

        private class LoginPayload
        {
            public Guid UserId { get; set; }
            public IList<string> Roles { get; set; } = new List<string>();
            public IList<Claim> Claims { get; set; } = new List<Claim>();
        }

        private async Task EnsureUserCanLoginAsync(ApplicationUser? user, bool requireExternal = false)
        {
            if (user == null)
            {
                await Task.Delay(TimeSpan.FromMilliseconds(200)).ConfigureAwait(false);
                throw new UnauthorizedAccessAppException("Credenciais inválidas.");
            }

            if (user.Tenant == null || !user.Tenant.IsActive)
                throw new UnauthorizedAccessAppException("Credenciais inválidas.");

            if (!user.IsActive || !await _userManager.IsEmailConfirmedAsync(user).ConfigureAwait(false))
                throw new UnauthorizedAccessAppException("Credenciais inválidas.");

            var logins = await _userManager.GetLoginsAsync(user).ConfigureAwait(false);

            if (requireExternal)
            {
                // fluxo exige login externo → precisa ter pelo menos 1 login externo
                if (logins.Count == 0)
                    throw new UnauthorizedAccessAppException("Credenciais inválidas.");
            }
            else
            {
                // fluxo exige login interno → não pode ter login externo
                if (logins.Count > 0)
                    throw new UnauthorizedAccessAppException("Credenciais inválidas.");
            }
        }

        private async Task<ApplicationUser?> FindValidUserByEmailAsync(string email)
        {
            var normalizedEmail = _userManager.NormalizeEmail(email);

            var user = await _userManager.Users
                .Include(u => u.Tenant)
                .Include(ur => ur.UserRoles)
                    .ThenInclude(r => r.Role)
                .FirstOrDefaultAsync(u => u.NormalizedEmail == normalizedEmail);

            return user;
        }

        private async Task<ApplicationUser?> FindValidUserByIdAsync(Guid userId)
        {

            var user = await _userManager.Users
                .Include(u => u.Tenant)
                .Include(ur => ur.UserRoles)
                    .ThenInclude(r => r.Role)
                .FirstOrDefaultAsync(u => u.Id == userId);

            return user;
        }

        public async Task RegisterAsync(RegisterRequest request)
        {
            var existing = await _userManager.FindByEmailAsync(request.Email).ConfigureAwait(false);
            if (existing != null)
                throw new ConflictException("Email já está em uso.");

            var user = new ApplicationUser
            {
                UserName = request.Email,
                Email = request.Email,
                FirstName = request.FirstName.SanitizeInput(),
                LastName = request.LastName.SanitizeInput(),
                IsActive = true,
                TenantId = _tenantService.GetTenantId()
            };

            user.FullName = $"{user.FirstName} {user.LastName}".Trim();
            user.NormalizedFullName = user.FullName.ToUpperInvariant();

            var result = await _userManager.CreateAsync(user, request.Password).ConfigureAwait(false);
            if (!result.Succeeded)
                throw new ValidationException(string.Join("; ", result.Errors.Select(e => e.Description)));

            var token = await _userManager.GenerateEmailConfirmationTokenAsync(user).ConfigureAwait(false);
            var encodedToken = WebEncoders.Base64UrlEncode(System.Text.Encoding.UTF8.GetBytes(token));

            SendConfirmationEmailInBackground(user.Email!, user.FirstName, user.Id.ToString(), encodedToken);
        }

        public async Task<TokenResponse> LoginAsync(LoginRequest request)
        {
            var user = await FindValidUserByEmailAsync(request.Email).ConfigureAwait(false);

            await EnsureUserCanLoginAsync(user, requireExternal: false).ConfigureAwait(false);

            var result = await _signInManager.CheckPasswordSignInAsync(user!, request.Password, lockoutOnFailure: true).ConfigureAwait(false);

            if (!result.Succeeded)
                throw new UnauthorizedAccessAppException("Credenciais inválidas.");

            await _userManager.ResetAccessFailedCountAsync(user!).ConfigureAwait(false);

            var roles = await _userManager.GetRolesAsync(user!).ConfigureAwait(false);
            //var claims = await _userManager.GetClaimsAsync(user!).ConfigureAwait(false);

            var accessToken = await _jwtTokenGenerator.GenerateToken(user!, roles);
            var refreshToken = GenerateRefreshToken();

            user!.RefreshToken = refreshToken;
            user.RefreshTokenExpiryTime = DateTime.UtcNow.AddDays(7);
            await _userManager.UpdateAsync(user).ConfigureAwait(false);

            var tokenResponse = new TokenResponse
            {
                AccessToken = accessToken,
                RefreshToken = refreshToken
            };

            return tokenResponse;
        }

        public async Task<TokenResponse> RefreshTokenAsync(string refreshToken)
        {
            var principal = _jwtTokenGenerator.GetPrincipalFromExpiredToken(refreshToken);
            var userEmail = principal.Identity?.Name;

            var user = await FindValidUserByEmailAsync(userEmail!).ConfigureAwait(false);

            if (user is null || !string.Equals(user.RefreshToken, refreshToken, StringComparison.Ordinal) || user.RefreshTokenExpiryTime <= DateTime.UtcNow)
                throw new BadRequestException("Invalid token");

            var roles = await _userManager.GetRolesAsync(user).ConfigureAwait(false);
            var claims = await _userManager.GetClaimsAsync(user).ConfigureAwait(false);

            var newAccessToken = await _jwtTokenGenerator.GenerateToken(user, roles);
            var newRefreshToken = GenerateRefreshToken();

            user.RefreshToken = newRefreshToken;
            user.RefreshTokenExpiryTime = DateTime.UtcNow.AddDays(7);
            await _userManager.UpdateAsync(user);

            return new TokenResponse
            {
                AccessToken = newAccessToken,
                RefreshToken = newRefreshToken
            };
        }

        private static string GenerateRefreshToken()
        {
            var randomNumber = new byte[32];
            using var rng = RandomNumberGenerator.Create();
            rng.GetBytes(randomNumber);
            return Convert.ToBase64String(randomNumber);
        }

        public ChallengeResult GetExternalLoginChallengeAsync(string provider, string redirectUrl)
        {
            var properties = _signInManager.ConfigureExternalAuthenticationProperties(provider, redirectUrl);

            return new ChallengeResult(provider, properties);
        }

        public async Task<string> ExternalLoginCallbackAsync(string transitionUrl, string? returnUrl)
        {
            ExternalLoginInfo info = await _signInManager.GetExternalLoginInfoAsync().ConfigureAwait(false)
                ?? throw new ValidationException("Não foi possível obter informações do provedor externo.");

            var user = await _userManager.FindByLoginAsync(info.LoginProvider, info.ProviderKey).ConfigureAwait(false);

            if (user == null)
            {
                var email = info.Principal.FindFirstValue(ClaimTypes.Email)
                    ?? throw new ValidationException("E-mail não fornecido pelo provedor externo.");

                user = new ApplicationUser
                {
                    UserName = email,
                    Email = email,
                    EmailConfirmed = true,
                    FirstName = info.Principal.FindFirstValue(ClaimTypes.GivenName) ?? "Usuário",
                    LastName = info.Principal.FindFirstValue(ClaimTypes.Surname) ?? "Externo",
                    CreatedAt = DateTime.UtcNow,
                    TenantId = _tenantService.GetTenantId(),
                };
                user.FullName = $"{user.FirstName} {user.LastName}".Trim();
                user.NormalizedFullName = user.FullName.ToUpperInvariant();

                var createResult = await _userManager.CreateAsync(user);
                if (!createResult.Succeeded)
                {
                    var errors = string.Join(", ", createResult.Errors.Select(e => e.Description));
                    throw new InvalidOperationAppException($"Falha ao criar usuário externo: {errors}");
                }

                var loginResult = await _userManager.AddLoginAsync(user, info);
                if (!loginResult.Succeeded)
                {
                    var errors = string.Join(", ", loginResult.Errors.Select(e => e.Description));
                    throw new InvalidOperationAppException($"Falha ao associar login externo: {errors}");
                }
            }

            var roles = await _userManager.GetRolesAsync(user).ConfigureAwait(false);
            var claims = await _userManager.GetClaimsAsync(user).ConfigureAwait(false);

            var code = TextExtensions.CreateOneTimeCode();
            var codeBytes = WebEncoders.Base64UrlDecode(code);
            var codeHash = Convert.ToHexString(SHA256.HashData(codeBytes));

            await _cacheService.SetAsync(
                $"ext_code:{codeHash}",
                new LoginPayload { UserId = user.Id, Roles = roles, Claims = claims },
                TimeSpan.FromMinutes(1)).ConfigureAwait(false);

            var parts = new List<string> { $"code={Uri.EscapeDataString(code)}" };
            if (!string.IsNullOrWhiteSpace(returnUrl))
                parts.Add($"returnUrl={Uri.EscapeDataString(returnUrl)}");

            return $"{transitionUrl}#{string.Join("&", parts)}";
        }

        public async Task<TokenResponse> ExchangeCode(string code)
        {
            if (!TextExtensions.TryGetCodeHash(code, out var codeHash))
                throw new BadRequestException("Código inválido ou expirado.");

            string cacheKey = $"ext_code:{codeHash}";

            var payload = await _cacheService.GetAsync<LoginPayload>(cacheKey).ConfigureAwait(false);

            if (payload == null)
                throw new BadRequestException("Código inválido ou expirado.");

            await _cacheService.RemoveAsync(cacheKey).ConfigureAwait(false);

            var user = await FindValidUserByIdAsync(payload.UserId).ConfigureAwait(false);

            await EnsureUserCanLoginAsync(user, requireExternal: true).ConfigureAwait(false);

            var accessToken = await _jwtTokenGenerator.GenerateToken(user!, payload.Roles);
            var refreshToken = GenerateRefreshToken();

            user!.RefreshToken = refreshToken;
            user.RefreshTokenExpiryTime = DateTime.UtcNow.AddDays(7);
            await _userManager.UpdateAsync(user).ConfigureAwait(false);

            var tokenResponse = new TokenResponse
            {
                AccessToken = accessToken,
                RefreshToken = refreshToken
            };

            return tokenResponse;
        }

        public async Task ConfirmEmailAsync(string userId, string token)
        {
            var user = await _userManager.FindByIdAsync(userId).ConfigureAwait(false);

            if (user == null)
                throw new BadRequestException("Link inválido ou expirado.");

            string decodedToken;
            try
            {
                var tokenBytes = WebEncoders.Base64UrlDecode(token);
                decodedToken = System.Text.Encoding.UTF8.GetString(tokenBytes);
            }
            catch
            {
                throw new BadRequestException("Link inválido ou expirado.");
            }

            var result = await _userManager.ConfirmEmailAsync(user, decodedToken).ConfigureAwait(false);

            if (!result.Succeeded)
                throw new BadRequestException("Link inválido ou expirado.");
        }

        public async Task ForgotPasswordAsync(ForgotPasswordRequest request)
        {
            var user = await _userManager.FindByEmailAsync(request.Email).ConfigureAwait(false);

            if (user != null && await _userManager.IsEmailConfirmedAsync(user).ConfigureAwait(false))
            {
                var token = await _userManager.GeneratePasswordResetTokenAsync(user).ConfigureAwait(false);
                var encodedToken = WebEncoders.Base64UrlEncode(System.Text.Encoding.UTF8.GetBytes(token));
                SendPasswordResetEmailInBackground(user.Email!, user.FirstName, encodedToken);
            }
        }

        public async Task ResetPasswordAsync(ResetPasswordRequest request)
        {
            var user = await _userManager.FindByEmailAsync(request.Email).ConfigureAwait(false);
            if (user == null)
            {
                await Task.Delay(TimeSpan.FromMilliseconds(100)).ConfigureAwait(false);
                return;
            }

            string decodedToken;
            try
            {
                var tokenBytes = WebEncoders.Base64UrlDecode(request.Token);
                decodedToken = System.Text.Encoding.UTF8.GetString(tokenBytes);
            }
            catch
            {
                throw new BadRequestException("Não foi possível redefinir a senha. Link inválido ou expirado.");
            }

            var result = await _userManager.ResetPasswordAsync(user, decodedToken, request.NewPassword).ConfigureAwait(false);

            if (!result.Succeeded)
                throw new BadRequestException("Não foi possível redefinir a senha. Link inválido ou expirado.");
        }

        public async Task<string> CreateInvitationAsync(InvitationRequest request)
        {
            var adminUser = await _loggedUserHelper.GetLoggedUserInfoAsync().ConfigureAwait(false);

            if (adminUser == null || !adminUser.HasRole("Developer,SuperAdmin,Owner,Admin"))
                throw new ForbiddenAccessException("Você não tem permissão para criar convites.");

            var user = await FindValidUserByEmailAsync(request.Email);

            if (user != null)
                throw new ConflictException("Já existe um usuário com este e-mail.");

            if (await _dbContext.Invitations.AnyAsync(i => i.Email == request.Email && i.Status == InvitationStatus.Pending))
                throw new ConflictException("Já existe um convite pendente para este e-mail.");

            var token = TextExtensions.CreateOneTimeCode(32);
            TextExtensions.TryGetCodeHash(token, out var tokenHash);

            var invitation = new Invitation
            {
                Email = request.Email,
                Token = tokenHash,
                ExpiresAt = DateTime.UtcNow.AddHours(72),
                InvitedByUserId = adminUser.UserId,
                TenantId = adminUser.TenantId,
                IsActive = true
            };

            _dbContext.Invitations.Add(invitation);
            await _dbContext.SaveChangesAsync();

            var encodedToken = WebEncoders.Base64UrlEncode(System.Text.Encoding.UTF8.GetBytes(token));

            SendInvitationEmailInBackground(request.Email, adminUser.TenantName, encodedToken);

            return "Convite criado e enviado com sucesso.";
        }

        public async Task<string> ValidateInviteToken(string token)
        {
            string? decodedToken = TextExtensions.DecodeOneTimeCode(token);

            if (!TextExtensions.TryGetCodeHash(decodedToken, out var tokenHash))
                throw new BadRequestException("Convite inválido ou expirado.");

            var invitation = await _dbContext.Invitations
                .AsNoTracking()
                .FirstOrDefaultAsync(i => i.Token == tokenHash && i.Status == InvitationStatus.Pending && i.ExpiresAt > DateTime.UtcNow);

            if (invitation == null)
            {
                throw new BadRequestException("Convite inválido ou expirado.");
            }

            return invitation.Email;
        }

        public async Task RegisterFromInviteAsync(RegisterFromInviteRequest request)
        {
            var strategy = _dbContext.Database.CreateExecutionStrategy();

            await strategy.ExecuteAsync(async () =>
            {
                await using var transaction = await _dbContext.Database.BeginTransactionAsync();

                try
                {                    
                    string? decodedToken = TextExtensions.DecodeOneTimeCode(request.Token);

                    if (!TextExtensions.TryGetCodeHash(decodedToken, out var tokenHash))
                        throw new BadRequestException("Convite inválido ou expirado.");

                    var invitation = await _dbContext.Invitations
                        .FirstOrDefaultAsync(i => i.Token == decodedToken && i.Status == InvitationStatus.Pending && i.ExpiresAt > DateTime.UtcNow);

                    if (invitation == null)
                        throw new BadRequestException("Convite inválido ou expirado.");

                    var user = new ApplicationUser
                    {
                        UserName = invitation.Email,
                        Email = invitation.Email,
                        FirstName = request.FirstName.SanitizeInput(),
                        LastName = request.LastName.SanitizeInput(),
                        EmailConfirmed = true,
                        IsActive = true,
                        TenantId = invitation.TenantId
                    };
                    user.FullName = $"{user.FirstName} {user.LastName}".Trim();
                    user.NormalizedFullName = user.FullName.ToUpperInvariant();

                    var result = await _userManager.CreateAsync(user, request.Password);

                    if (!result.Succeeded)
                        throw new ValidationException(string.Join("; ", result.Errors.Select(e => e.Description)));

                    // Atribui a role padrão 'User' ou outra que você desejar
                    await _userManager.AddToRoleAsync(user, "User");

                    // Invalida o convite
                    invitation.Status = InvitationStatus.Accepted;
                    await _dbContext.SaveChangesAsync();

                    await transaction.CommitAsync();
                }
                catch (Exception)
                {
                    await transaction.RollbackAsync();
                    throw;
                }
            });
        }

        private void SendEmailInBackground(string toEmail, string subject, Func<IEmailTemplateService, Task<string>> templateBuilder)
        {
            Task.Run(async () =>
            {
                using var scope = _serviceProvider.CreateScope();
                var emailSender = scope.ServiceProvider.GetRequiredService<IEmailSender>();
                var templateService = scope.ServiceProvider.GetRequiredService<IEmailTemplateService>();
                var logger = scope.ServiceProvider.GetRequiredService<ILogger<AuthService>>();
                try
                {
                    var body = await templateBuilder(templateService);
                    await emailSender.SendEmailAsync(toEmail, subject, body);
                    logger.LogInformation("E-mail '{Subject}' enviado com sucesso para {Email}", subject, toEmail);
                }
                catch (Exception ex)
                {
                    logger.LogError(ex, "Falha ao enviar e-mail '{Subject}' para {Email}", subject, toEmail);
                }
            });
        }

        private void SendConfirmationEmailInBackground(string email, string userName, string userId, string encodedToken)
        {
            var confirmLink = $"{_urlSettings.FrontendBaseUrl}{_urlSettings.EmailConfirmationPath}?userId={userId}&token={encodedToken}";
            SendEmailInBackground(email, "Confirme seu cadastro",
                templateService => templateService.GetEmailConfirmationTemplateAsync(userName, confirmLink));
        }

        private void SendPasswordResetEmailInBackground(string email, string userName, string encodedToken)
        {
            var resetLink = $"{_urlSettings.FrontendBaseUrl}{_urlSettings.PasswordResetPath}?email={Uri.EscapeDataString(email)}&token={encodedToken}";
            SendEmailInBackground(email, "Redefinição de senha",
                templateService => templateService.GetPasswordResetTemplateAsync(userName, resetLink));
        }

        private void SendInvitationEmailInBackground(string email, string tenantName, string encodedToken)
        {
            var invitationLink = $"{_urlSettings.FrontendBaseUrl}{_urlSettings.ValidateInvitationPath}/{encodedToken}";
            SendEmailInBackground(email, $"Convite para {tenantName}",
                templateService => templateService.GetUserInvitationTemplateAsync(tenantName, invitationLink));
        }

    }
}