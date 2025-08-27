using System.ComponentModel.DataAnnotations;

namespace GariusWeb.Api.Application.Dtos.ServiceAccounts
{
    public class CreateServiceAccountRequest
    {
        [Required]
        public string PartnerName { get; set; } = string.Empty;

        [Required]
        public ICollection<string> Scopes { get; set; } = [];
    }
}
