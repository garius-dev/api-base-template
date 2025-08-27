using System.ComponentModel.DataAnnotations;

namespace GariusWeb.Api.Application.Dtos.Auth
{
    public class RegisterFromInviteRequest
    {
        [Required]
        public string Token { get; set; } = string.Empty;

        [Required]
        [StringLength(100)]
        public string FirstName { get; set; } = default!;

        [Required]
        [StringLength(100)]
        public string LastName { get; set; } = default!;

        [Required]
        [DataType(DataType.Password)]
        [StringLength(100, MinimumLength = 6)]
        public string Password { get; set; } = default!;

        [Required]
        [DataType(DataType.Password)]
        [Compare("Password", ErrorMessage = "As senhas não coincidem.")]
        public string ConfirmPassword { get; set; } = default!;
    }
}