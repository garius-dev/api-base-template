using GariusWeb.Api.Application.Interfaces;
using GariusWeb.Api.Domain.Abstractions;

namespace GariusWeb.Api.Application.Dtos.Tenants
{
    public class TenantResponse
    {
        public Guid Id { get; set; }
        public string Name { get; set; } = string.Empty;
        public bool IsActive { get; set; }
        public bool IsDummy { get; set; }
        public DateTime CreatedAt { get; set; }
    }
}
