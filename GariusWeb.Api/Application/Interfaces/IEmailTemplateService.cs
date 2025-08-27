namespace GariusWeb.Api.Application.Interfaces
{
    public interface IEmailTemplateService
    {
        Task<string> GetEmailConfirmationTemplateAsync(string userName, string confirmationLink);
        Task<string> GetPasswordResetTemplateAsync(string userName, string resetLink);
        Task<string> GetUserInvitationTemplateAsync(string tenantName, string invitationLink);
    }
}
