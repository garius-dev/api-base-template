using GariusWeb.Api.Application.Dtos.Auth;
using GariusWeb.Api.Application.Dtos.Invitations;
using Microsoft.AspNetCore.Mvc;

namespace GariusWeb.Api.Application.Interfaces
{
    public interface IAuthService
    {
        Task RegisterAsync(RegisterRequest request);

        Task<TokenResponse> LoginAsync(LoginRequest request);

        Task<TokenResponse> RefreshTokenAsync(string refreshToken);

        ChallengeResult GetExternalLoginChallengeAsync(string provider, string redirectUrl);

        Task<string> ExternalLoginCallbackAsync(string transitionUrl, string? returnUrl);

        Task<TokenResponse> ExchangeCode(string code);

        Task ConfirmEmailAsync(string userId, string token);

        Task ForgotPasswordAsync(ForgotPasswordRequest request);

        Task ResetPasswordAsync(ResetPasswordRequest request);


        Task<string> CreateInvitationAsync(InvitationRequest request);
        Task<string> ValidateInviteToken(string token);
        Task RegisterFromInviteAsync(RegisterFromInviteRequest request);
    }
}