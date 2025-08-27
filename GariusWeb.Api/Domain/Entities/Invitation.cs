using GariusWeb.Api.Domain.Abstractions;
using GariusWeb.Api.Domain.Abstractions.Interfaces;
using GariusWeb.Api.Domain.Constants;
using GariusWeb.Api.Domain.Entities.Identity;
using System.ComponentModel.DataAnnotations.Schema;

namespace GariusWeb.Api.Domain.Entities
{
    public class Invitation : BaseEntity, ITenantEntity
    {
        public string Email { get; set; } = string.Empty;

        public string Token { get; set; } = string.Empty;

        public DateTime ExpiresAt { get; set; }

        public string Status { get; set; } = InvitationStatus.Pending;

        // Chave estrangeira para o usuário que convidou (Admin)
        public Guid InvitedByUserId { get; set; }
        public virtual ApplicationUser? InvitedByUser { get; set; }

        // Implementação da interface ITenantEntity
        [ForeignKey(nameof(Tenant))]
        public Guid TenantId { get; set; }
        public virtual Tenant Tenant { get; set; } = default!;
    }
}
