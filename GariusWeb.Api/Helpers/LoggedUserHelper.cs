using GariusWeb.Api.Application.Dtos.SystemUsers;
using GariusWeb.Api.Application.Exceptions;
using GariusWeb.Api.Application.Interfaces.SystemUsers;
using System.Security.Claims;

namespace GariusWeb.Api.Helpers
{
    public class LoggedUserHelper
    {
        private readonly ISystemUserResolver _systemUserResolver;
        private readonly IHttpContextAccessor _httpContextAccessor;

        public LoggedUserHelper(
            ISystemUserResolver systemUserResolver,
            IHttpContextAccessor httpContextAccessor)
        {
            _systemUserResolver = systemUserResolver;
            _httpContextAccessor = httpContextAccessor;
        }

        public async Task<SystemUser> GetLoggedUserInfoAsync()
        {
            var httpContext = _httpContextAccessor.HttpContext;
            if (httpContext == null || httpContext.User == null)
                throw new UnauthorizedAccessAppException("Usuário não autenticado.");

            var userPrincipal = httpContext?.User;
            if (userPrincipal == null || userPrincipal.Identity == null || !userPrincipal.Identity.IsAuthenticated)
                throw new UnauthorizedAccessAppException("Usuário não autenticado.");

            var email = userPrincipal.FindFirstValue(ClaimTypes.Email);
            var name = userPrincipal.Identity?.Name ?? email ?? "";

            if (string.IsNullOrEmpty(email))
                throw new UnauthorizedAccessAppException("Não foi possível obter o e-mail do usuário logado.");

            var appUser = await _systemUserResolver.FindByEmailAsync(email);

            if (appUser == null)
                throw new NotFoundException("Usuário logado não encontrado.");

            return appUser;
        }
    }
}