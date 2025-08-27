using GariusWeb.Api.Domain.Abstractions.Interfaces;
using Microsoft.AspNetCore.Identity;
using NpgsqlTypes;
using System.ComponentModel.DataAnnotations;
using System.ComponentModel.DataAnnotations.Schema;

namespace GariusWeb.Api.Domain.Entities.Identity
{
    public class ApplicationUser : IdentityUser<Guid>, IBaseEntity, ITenantEntity
    {
        [Required(ErrorMessage = "O 'Nome' é obrigatório.")]
        [MaxLength(100, ErrorMessage = "O 'Nome' deve ter no máximo 100 caracteres.")]
        public string FirstName { get; set; } = default!;

        [Required(ErrorMessage = "O 'Sobrenome' é obrigatório.")]
        [MaxLength(100, ErrorMessage = "O 'Sobrenome' deve ter no máximo 100 caracteres.")]
        public string LastName { get; set; } = default!;

        [MaxLength(201, ErrorMessage = "O 'Nome Completo' deve ter no máximo 201 caracteres.")]
        public string FullName { get; set; } = default!;

        public string NormalizedFullName { get; set; } = default!;

        public DateTime CreatedAt { get; set; } = DateTime.UtcNow;
        public DateTime? UpdatedAt { get; set; }
        public bool IsActive { get; set; } = true;

        public string? RefreshToken { get; set; }
        public DateTime RefreshTokenExpiryTime { get; set; }

        public string? EmailSearch { get; private set; }
        public NpgsqlTsVector SearchVector { get; set; } = null!;

        public virtual ICollection<ApplicationUserRole> UserRoles { get; set; } = new List<ApplicationUserRole>();
        public virtual ICollection<ApplicationUserClaim> Claims { get; set; } = new List<ApplicationUserClaim>();


        [ForeignKey(nameof(Tenant))]
        public Guid TenantId { get; set; }
        public virtual Tenant Tenant { get; set; } = default!;
    }
}