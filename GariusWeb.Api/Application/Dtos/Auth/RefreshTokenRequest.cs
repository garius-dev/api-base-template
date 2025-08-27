using System.ComponentModel.DataAnnotations;

namespace GariusWeb.Api.Application.Dtos.Auth
{
    public class RefreshTokenRequest
    {
        [Required]
        public string RefreshToken { get; set; } = default!;
    }
}
