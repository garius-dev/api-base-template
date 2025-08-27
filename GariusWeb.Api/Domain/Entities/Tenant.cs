using GariusWeb.Api.Domain.Abstractions;

namespace GariusWeb.Api.Domain.Entities
{
    public class Tenant : BaseEntity
    {
        public string Name { get; set; } = string.Empty;
        public bool IsDummy { get; set; } = false;
    }
}
