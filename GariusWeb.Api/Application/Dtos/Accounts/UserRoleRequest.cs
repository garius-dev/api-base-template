using System.ComponentModel.DataAnnotations;

namespace GariusWeb.Api.Application.Dtos.Accounts
{
    public class UserRoleRequest
    {
        [Required(ErrorMessage = "O nome da role é obrigatório.")]
        public string RoleName { get; set; } = string.Empty;
    }
}
