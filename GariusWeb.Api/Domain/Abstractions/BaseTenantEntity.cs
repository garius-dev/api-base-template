using GariusWeb.Api.Domain.Abstractions.Interfaces;
using GariusWeb.Api.Domain.Entities;
using System.ComponentModel.DataAnnotations.Schema;

namespace GariusWeb.Api.Domain.Abstractions
{
    public abstract class BaseTenantEntity : BaseEntity, ITenantEntity
    {
        [ForeignKey(nameof(Tenant))]
        public Guid TenantId { get; set; }
        public virtual Tenant Tenant { get; set; }
    }
}
