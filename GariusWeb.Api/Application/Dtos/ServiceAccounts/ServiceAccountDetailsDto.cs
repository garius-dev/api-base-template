namespace GariusWeb.Api.Application.Dtos.ServiceAccounts
{
    public class ServiceAccountDetailsDto
    {
        public Guid Id { get; set; }
        public string PartnerName { get; set; } = string.Empty;
        public string ClientId { get; set; } = string.Empty;
        public ICollection<string> Scopes { get; set; } = [];
        public bool IsActive { get; set; }
        public DateTime CreatedAt { get; set; }
        public DateTime? LastUsedAt { get; set; }
    }
}
