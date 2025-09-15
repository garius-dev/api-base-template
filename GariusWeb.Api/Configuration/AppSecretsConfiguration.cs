using Npgsql;
using System.ComponentModel.DataAnnotations;

namespace GariusWeb.Api.Configuration
{
    public static class AppSecretsConfiguration
    {
        public enum TenantMode
        {
            Dedicated = 0,
            SaaS = 1
        }

        public class TenantSettings
        {
            public TenantMode Mode { get; set; } = TenantMode.Dedicated; // "SaaS" or "Dedicated"
            public Guid DefaultTenantId { get; set; }
        }

        public class HashidSettings
        {
            public string SecretKey { get; set; } = string.Empty;
        }

        public class UrlSettings
        {
            public string FrontendBaseUrl { get; set; } = string.Empty;

            public string EmailConfirmationPath { get; set; } = "/confirm-email";
            public string PasswordResetPath { get; set; } = "/reset-password";
            public string InvitationPath { get; set; } = "/register-from-invite";
            public string ValidateInvitationPath { get; set; } = "/intivations/validate";
        }
                
        public class ConnectionStringSettings
        {
            public string Host { get; set; } = string.Empty;
            public string Port { get; set; } = "5432";
            public string Database { get; set; } = string.Empty;
            public DatabaseUser Users { get; set; } = new();

            public string GetConnectionString(bool isDevelopment, bool isMigrateOnly, bool isDockerRun)
            {
                var user = isMigrateOnly ? Users.SuperAdmin :
                   (isDevelopment ? Users.Admin : Users.Common);

                var host = isDevelopment && !isDockerRun ? "localhost" : Host;
                var builder = new NpgsqlConnectionStringBuilder
                {
                    Host = host,
                    Port = int.TryParse(Port, out var p) ? p : 5432,
                    Database = Database,
                    Username = user.Name,
                    Password = user.Pwd,
                };

                return builder.ConnectionString;
            }

            public string GetRootConnectionString(bool isDevelopment, bool isDockerRun)
            {
                var host = isDevelopment && !isDockerRun ? "localhost" : Host;
                var root = Users.SuperAdmin;
                var builder = new NpgsqlConnectionStringBuilder
                {
                    Host = host,
                    Port = int.TryParse(Port, out var p) ? p : 5432,
                    Database = "postgres",
                    Username = root.Name,
                    Password = root.Pwd,
                };

                return builder.ConnectionString;
            }

            public void Validate()
            {
                if (string.IsNullOrWhiteSpace(Host)) throw new InvalidOperationException("ConnectionStringSettings.Host is missing.");
                if (string.IsNullOrWhiteSpace(Database)) throw new InvalidOperationException("ConnectionStringSettings.Database is missing.");
                if (Users == null) throw new InvalidOperationException("ConnectionStringSettings.Users is missing.");
                if (string.IsNullOrWhiteSpace(Users.SuperAdmin?.Name) || string.IsNullOrWhiteSpace(Users.SuperAdmin?.Pwd))
                    throw new InvalidOperationException("SuperAdmin credentials missing.");
                if (string.IsNullOrWhiteSpace(Users.Admin?.Name) || string.IsNullOrWhiteSpace(Users.Admin?.Pwd))
                    throw new InvalidOperationException("Admin credentials missing.");
                if (string.IsNullOrWhiteSpace(Users.Common?.Name) || string.IsNullOrWhiteSpace(Users.Common?.Pwd))
                    throw new InvalidOperationException("Common credentials missing.");
            }
        }

        public class DatabaseUser
        {
            public DatabaseUserSettings SuperAdmin { get; set; } = new();
            public DatabaseUserSettings Admin { get; set; } = new();
            public DatabaseUserSettings Common { get; set; } = new();
        }

        public class DatabaseUserSettings
        {
            public string Name { get; set; } = string.Empty;
            public string Pwd { get; set; } = string.Empty;
        }

        public class GoogleExternalAuthSettings
        {
            [Required(ErrorMessage = "O 'ClientId' do Google é obrigatório.")]
            public string ClientId { get; set; } = string.Empty;

            [Required(ErrorMessage = "O 'ClientSecret' do Google é obrigatório.")]
            public string ClientSecret { get; set; } = string.Empty;
        }

        public class MicrosoftExternalAuthSettings
        {
            [Required(ErrorMessage = "O 'ClientId' da Microsoft é obrigatório.")]
            public string ClientId { get; set; } = string.Empty;

            [Required(ErrorMessage = "O 'ClientSecret' da Microsoft é obrigatório.")]
            public string ClientSecret { get; set; } = string.Empty;

            [Required(ErrorMessage = "O 'TenantId' da Microsoft é obrigatório.")]
            public string TenantId { get; set; } = string.Empty;
        }

        public class CloudflareSettings
        {
            [Required(ErrorMessage = "A chave pública 'SiteKey' do Cloudflare é obrigatória.")]
            public string SiteKey { get; set; } = string.Empty;

            [Required(ErrorMessage = "A chave secreta 'SecretKey' do Cloudflare é obrigatória.")]
            public string SecretKey { get; set; } = string.Empty;
        }

        public class CloudinarySettings
        {
            [Required(ErrorMessage = "O 'CloudName' do Cloudinary é obrigatório.")]
            public string CloudName { get; set; } = string.Empty;

            [Required(ErrorMessage = "A 'ApiKey' do Cloudinary é obrigatória.")]
            public string ApiKey { get; set; } = string.Empty;

            [Required(ErrorMessage = "A 'ApiSecret' do Cloudinary é obrigatória.")]
            public string ApiSecret { get; set; } = string.Empty;
        }

        public class ResendSettings
        {
            [Required(ErrorMessage = "A 'ApiKey' do Resend é obrigatória.")]
            public string ApiKey { get; set; } = string.Empty;

            [Required(ErrorMessage = "O e-mail de envio padrão ('FromEmail') do Resend é obrigatório.")]
            [EmailAddress(ErrorMessage = "O 'FromEmail' do Resend deve ser um endereço de e-mail válido.")]
            public string FromEmail { get; set; } = string.Empty;
        }

        public class JwtSettings
        {
            [Required(ErrorMessage = "A chave secreta do JWT ('Secret') é obrigatória.")]
            public string Secret { get; set; } = string.Empty;

            [Required(ErrorMessage = "O emissor do JWT ('Issuer') é obrigatório.")]
            public string Issuer { get; set; } = string.Empty;

            [Range(1, 1440, ErrorMessage = "O tempo de expiração do JWT ('ExpirationInMinutes') deve estar entre 1 e 1440 minutos.")]
            public int ExpirationInMinutes { get; set; }

            [Required(ErrorMessage = "A audiência do JWT ('Audience') é obrigatória.")]
            public string Audience { get; set; } = string.Empty;

            public string EmailConfirmationUrl { get; set; } = default!;
            public string PasswordResetUrl { get; set; } = default!;
        }
                
        public class RedisSettings
        {
            public string Host { get; set; } = "localhost";
            public string Port { get; set; } = "6379";
            public string Pwd { get; set; } = string.Empty;

            public string GetConfiguration(bool isDevelopment, bool isDockerRun)
            {
                var host = isDevelopment && !isDockerRun ? "localhost" : Host;
                return $"{host}:{Port},password={Pwd}";
            }

            public void Validate()
            {
                if (string.IsNullOrWhiteSpace(Host)) throw new InvalidOperationException("RedisSettings.Host is missing.");
                if (string.IsNullOrWhiteSpace(Port)) throw new InvalidOperationException("RedisSettings.Port is missing.");
                if (string.IsNullOrWhiteSpace(Pwd)) throw new InvalidOperationException("RedisSettings.Pwd is missing.");
            }
        }
    }
}