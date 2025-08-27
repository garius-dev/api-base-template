using System.ComponentModel.DataAnnotations;

namespace GariusWeb.Api.Application.Dtos.Invitations
{
    public class InvitationRequest
    {
        [Required, EmailAddress]
        public string Email { get; set; } = string.Empty;
    }
}
