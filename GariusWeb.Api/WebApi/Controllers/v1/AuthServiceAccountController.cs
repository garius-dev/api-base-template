using Asp.Versioning;
using GariusWeb.Api.Application.Dtos.Auth;
using GariusWeb.Api.Application.Dtos.Invitations;
using GariusWeb.Api.Application.Dtos.ServiceAccounts;
using GariusWeb.Api.Application.Exceptions;
using GariusWeb.Api.Application.Interfaces;
using GariusWeb.Api.Helpers;
using Microsoft.AspNetCore.Authorization;
using Microsoft.AspNetCore.Http;
using Microsoft.AspNetCore.Mvc;

namespace GariusWeb.Api.WebApi.Controllers.v1
{
    [ApiController]
    [Route("api/v{version:apiVersion}/auth/svc")]
    [ApiVersion("1.0")]
    public class AuthServiceAccountController : ControllerBase
    {
        private readonly IAuthService _authService;
        private readonly IServiceAccountService _serviceAccountService; // Adicionar
        private readonly IJwtTokenGenerator _jwtTokenGenerator;


        public AuthServiceAccountController(
            IAuthService authService,
            IServiceAccountService serviceAccountService, // Adicionar
            IJwtTokenGenerator jwtTokenGenerator)
        {
            _authService = authService;
            _serviceAccountService = serviceAccountService; // Adicionar
            _jwtTokenGenerator = jwtTokenGenerator;
        }

        [AllowAnonymous]
        [HttpPost("token")]
        [Consumes("application/x-www-form-urlencoded")]
        public async Task<IActionResult> Token([FromForm] TokenRequest request)
        {
            if (!string.Equals(request.GrantType, "client_credentials", StringComparison.Ordinal))
            {
                throw new BadRequestException("grant_type inválido.");
            }

            var serviceAccount = await _serviceAccountService.ValidateCredentialsAsync(request.ClientId, request.ClientSecret);

            if (serviceAccount == null)
            {
                throw new UnauthorizedAccessAppException("client_id ou client_secret inválido.");
            }

            var token = _jwtTokenGenerator.GenerateServiceAccountToken(serviceAccount);
            return Ok(ApiResponse<string>.Ok(token));
        }


        [HttpPost("create")]
        [Authorize(Roles = "SuperAdmin,Developer")]
        public async Task<IActionResult> Create(CreateServiceAccountRequest request)
        {
            var result = await _serviceAccountService.CreateServiceAccountAsync(request);
            return CreatedAtAction(nameof(GetById), new { id = result.Id }, ApiResponse<CreateServiceAccountResponse>.Ok(result));
        }

        [HttpGet("get-all")]
        [Authorize(Roles = "SuperAdmin,Developer")]
        public async Task<IActionResult> GetAll()
        {
            var accounts = await _serviceAccountService.GetAllServiceAccountsAsync();
            return Ok(ApiResponse<IEnumerable<ServiceAccountDetailsDto>>.Ok(accounts));
        }

        [HttpGet("{id:guid}", Name = "GetById")]
        [Authorize(Roles = "SuperAdmin,Developer")]
        public async Task<IActionResult> GetById(Guid id)
        {
            // Implementação de GetById pode ser adicionada no service se necessário
            var account = (await _serviceAccountService.GetAllServiceAccountsAsync()).FirstOrDefault(a => a.Id == id);
            if (account == null) throw new NotFoundException("Conta de serviço não encontrada.");
            return Ok(ApiResponse<ServiceAccountDetailsDto>.Ok(account));
        }

        [HttpPatch("{id:guid}/deactivate")]
        [Authorize(Roles = "SuperAdmin,Developer")]
        public async Task<IActionResult> Deactivate(Guid id)
        {
            await _serviceAccountService.DeactivateServiceAccountAsync(id);
            return NoContent();
        }

        [HttpPatch("{id:guid}/activate")]
        [Authorize(Roles = "SuperAdmin,Developer")]
        public async Task<IActionResult> Activate(Guid id)
        {
            await _serviceAccountService.ActivateServiceAccountAsync(id);
            return NoContent();
        }


        
    }
}
