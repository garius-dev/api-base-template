using GariusWeb.Api.Application.Interfaces;
using System.Reflection;

namespace GariusWeb.Api.Application.Services
{
    public class EmailTemplateService : IEmailTemplateService
    {
        private readonly IWebHostEnvironment _env;

        public EmailTemplateService(IWebHostEnvironment env)
        {
            _env = env;
        }

        private async Task<string> LoadAndPopulateTemplate(string templateName, Dictionary<string, string> placeholders)
        {
            var templatePath = Path.Combine(_env.ContentRootPath, "EmailTemplates", templateName);

            if (!File.Exists(templatePath))
            {
                // Fallback para recurso embutido se o arquivo físico não for encontrado
                var assembly = Assembly.GetExecutingAssembly();
                var resourceName = $"GariusWeb.Api.EmailTemplates.{templateName}";
                using var stream = assembly.GetManifestResourceStream(resourceName);
                if (stream == null)
                {
                    throw new FileNotFoundException($"Template de e-mail não encontrado: {templateName}");
                }
                using var reader = new StreamReader(stream);
                var content = await reader.ReadToEndAsync();
                return Populate(content, placeholders);
            }

            var fileContent = await File.ReadAllTextAsync(templatePath);
            return Populate(fileContent, placeholders);
        }

        private static string Populate(string content, Dictionary<string, string> placeholders)
        {
            return placeholders.Aggregate(content, (current, placeholder) =>
                current.Replace($"{{{{{placeholder.Key}}}}}", placeholder.Value));
        }

        public Task<string> GetEmailConfirmationTemplateAsync(string userName, string confirmationLink)
        {
            var placeholders = new Dictionary<string, string>
            {
                { "UserName", userName },
                { "ConfirmationLink", confirmationLink }
            };
            return LoadAndPopulateTemplate("EmailConfirmation.html", placeholders);
        }

        public Task<string> GetPasswordResetTemplateAsync(string userName, string resetLink)
        {
            var placeholders = new Dictionary<string, string>
            {
                { "UserName", userName },
                { "ResetLink", resetLink }
            };
            return LoadAndPopulateTemplate("PasswordReset.html", placeholders);
        }

        public Task<string> GetUserInvitationTemplateAsync(string tenantName, string invitationLink)
        {
            var placeholders = new Dictionary<string, string>
            {
                { "TenantName", tenantName },
                { "InvitationLink", invitationLink }
            };
            return LoadAndPopulateTemplate("UserInvitation.html", placeholders);
        }
    }
}
