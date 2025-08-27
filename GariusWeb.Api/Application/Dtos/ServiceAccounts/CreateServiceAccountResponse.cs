namespace GariusWeb.Api.Application.Dtos.ServiceAccounts
{
    public class CreateServiceAccountResponse
    {
        public Guid Id { get; set; }
        public string PartnerName { get; set; } = string.Empty;
        public string ClientId { get; set; } = string.Empty;
        public string ClientSecret { get; set; } = string.Empty; // Retornado apenas na criação
        public IList<string> Scopes { get; set; } = [];
    }
}
