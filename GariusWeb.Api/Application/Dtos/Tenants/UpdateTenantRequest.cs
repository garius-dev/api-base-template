using System.ComponentModel.DataAnnotations;

namespace GariusWeb.Api.Application.Dtos.Tenants
{
    public class UpdateTenantRequest
    {
        [Required(ErrorMessage = "O nome do tenant é obrigatório.")]
        [StringLength(100, MinimumLength = 3, ErrorMessage = "O nome deve ter entre 3 e 100 caracteres.")]
        public string Name { get; set; } = string.Empty;

        public bool IsDummy { get; set; }
    }
}
