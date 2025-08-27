using GariusWeb.Api.Domain.Abstractions;

namespace GariusWeb.Api.Domain.Entities.ServiceAccount
{
    // Renamed to avoid matching the containing namespace
    public class ServiceAccountEntity : BaseEntity
    {
        public string PartnerName { get; set; } = string.Empty;
        public string ClientId { get; set; } = string.Empty;
        public string HashedClientSecret { get; set; } = string.Empty;
        public ICollection<string> Scopes { get; set; } = [];
    }
}
