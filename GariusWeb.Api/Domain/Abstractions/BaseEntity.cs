using GariusWeb.Api.Domain.Abstractions.Interfaces;
using System.ComponentModel.DataAnnotations;

namespace GariusWeb.Api.Domain.Abstractions
{
    public abstract class BaseEntity : IBaseEntity
    {
        [Key]
        public Guid Id { get; set; }
        public bool IsActive { get; set; }
        public DateTime CreatedAt { get; set; } = DateTime.UtcNow;
        public DateTime? UpdatedAt { get; set; } = DateTime.UtcNow;
    }
}
