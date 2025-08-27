using NpgsqlTypes;

namespace GariusWeb.Api.Domain.Abstractions.Interfaces
{
    public interface IBaseEntity
    {
        Guid Id { get; set; }
        bool IsActive { get; set; }
        DateTime CreatedAt { get; set; }
        DateTime? UpdatedAt { get; set; }
    }
}