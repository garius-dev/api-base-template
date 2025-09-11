using Asp.Versioning;
using Asp.Versioning.ApiExplorer;
using GariusWeb.Api.Application.Interfaces;
using GariusWeb.Api.Application.Interfaces.SystemUsers;
using GariusWeb.Api.Application.Mappers;
using GariusWeb.Api.Application.Services;
using GariusWeb.Api.Application.Services.SystemUsers;
using GariusWeb.Api.Configuration;
using GariusWeb.Api.Domain.Constants;
using GariusWeb.Api.Domain.Entities.Identity;
using GariusWeb.Api.Domain.Interfaces;
using GariusWeb.Api.Extensions;
using GariusWeb.Api.Helpers;
using GariusWeb.Api.Infrastructure.Auth;
using GariusWeb.Api.Infrastructure.Data;
using GariusWeb.Api.Infrastructure.Data.Seed;
using GariusWeb.Api.Infrastructure.Middleware;
using GariusWeb.Api.Infrastructure.Services;
using GariusWeb.Api.WebApi.Dev;
using Google.Api;
using Microsoft.AspNetCore.Authentication.Cookies;
using Microsoft.AspNetCore.Authentication.JwtBearer;
using Microsoft.AspNetCore.Authorization;
using Microsoft.AspNetCore.DataProtection;
using Microsoft.AspNetCore.Diagnostics.HealthChecks;
using Microsoft.AspNetCore.HttpOverrides;
using Microsoft.AspNetCore.Identity;
using Microsoft.EntityFrameworkCore;
using Microsoft.Extensions.Diagnostics.HealthChecks;
using Microsoft.IdentityModel.Tokens;
using Serilog;
using StackExchange.Redis;
using System.Text;
using System.Text.Json;
using System.Xml.Linq;
using static GariusWeb.Api.Configuration.AppSecretsConfiguration;

//Add-Migration AddUsersSearchIndex -Context ApplicationDbContext

var builder = WebApplication.CreateBuilder(args);

// --- CONFIGURA��O DAS VARI�VEIS DE AMBIENTE ---
var enableHttpsRedirect =
    builder.Configuration.GetValue<bool?>("HTTPS_REDIRECTION_ENABLED") ?? true;

bool enableDebugEndpoints =
    builder.Configuration.GetValue<bool?>("DEV_ENDPOINTS_ENABLED") ?? false;

bool enableSwagger =
    builder.Configuration.GetValue<bool?>("SWAGGER_ENABLED") ?? false;

bool migrateOnly =
    builder.Configuration.GetValue<bool?>("MIGRATE_ONLY") ?? false;

// --- CONFIGURA��O DO LOG ---
Log.Logger = new LoggerConfiguration()
    .WriteTo.Console()
    .CreateBootstrapLogger();

if (builder.Environment.IsDevelopment())
{
    Serilog.Debugging.SelfLog.Enable(m => Console.Error.WriteLine(m));
}

builder.Host.UseSerilog((ctx, services, lc) => lc
    .ReadFrom.Configuration(ctx.Configuration)
    .ReadFrom.Services(services)
    .Enrich.FromLogContext()
    .Enrich.WithProperty("app", "garius-api")
    .Enrich.WithProperty("env", ctx.HostingEnvironment.EnvironmentName));

// --- CONFIGURA��O DO GOOGLE SECRETS ---
var secretConfig = builder.AddGoogleSecrets("GariusTechAppSecrets");

// --- ADICIONA O GOOGLE SECRETS � CONFIGURA��O GLOBAL ---
builder.Configuration.AddConfiguration(secretConfig);

// --- CONFIGURA��O DE CONEX�O DO REDIS E DB ---
var redisConfig = builder.Configuration[$"RedisSettings:{builder.Environment.EnvironmentName}:Configuration"];

var connectionStringSettings = builder.Configuration.GetSection("ConnectionStringSettings").Get<ConnectionStringSettings>()!;
var connectionString = connectionStringSettings.GetConnectionString(builder.Environment.IsDevelopment(), migrateOnly);

if (string.IsNullOrEmpty(connectionString))
{
    Log.Fatal("DB: GET CONNECTION FAILED.");
    Log.CloseAndFlush();
    Environment.Exit(1);
}

if (string.IsNullOrWhiteSpace(redisConfig))
{
    Log.Fatal("REDIS: GET CONNECTION FAILED.");
    Log.CloseAndFlush();
    Environment.Exit(1);
}

// --- CONFIGURA��O DO RATE LIMITER ---
builder.Services.AddCustomRateLimiter();

// --- CONFIGURA��O DO CORS ---
builder.Services.AddCustomCors(builder.Environment);

// --- CONFIGURA��O DO SWAGGER ---
builder.Services.AddEndpointsApiExplorer();
builder.Services.AddSwaggerGen();
builder.Services.ConfigureOptions<SwaggerConfiguration>();

// --- CONFIGURA��O DO VERSIONAMENTO DO SWAGGER ---
builder.Services.AddApiVersioning(options =>
{
    options.DefaultApiVersion = new ApiVersion(1, 0);
    options.AssumeDefaultVersionWhenUnspecified = true;
    options.ReportApiVersions = true;
    options.ApiVersionReader = new UrlSegmentApiVersionReader();
}).AddApiExplorer(options =>
{
    options.GroupNameFormat = "'v'VVV";
    options.SubstituteApiVersionInUrl = true;
});

// --- LOAD DAS SECRETS ---
builder.Services.AddValidatedSettings<ConnectionStringSettings>(builder.Configuration, "ConnectionStringSettings");
builder.Services.AddValidatedSettings<GoogleExternalAuthSettings>(builder.Configuration, "GoogleExternalAuthSettings");
builder.Services.AddValidatedSettings<MicrosoftExternalAuthSettings>(builder.Configuration, "MicrosoftExternalAuthSettings");
builder.Services.AddValidatedSettings<CloudflareSettings>(builder.Configuration, "CloudflareSettings");
builder.Services.AddValidatedSettings<CloudinarySettings>(builder.Configuration, "CloudinarySettings");
builder.Services.AddValidatedSettings<ResendSettings>(builder.Configuration, "ResendSettings");
builder.Services.AddValidatedSettings<JwtSettings>(builder.Configuration, "JwtSettings");
builder.Services.AddValidatedSettings<RedisSettings>(builder.Configuration, "RedisSettings");
builder.Services.AddValidatedSettings<HashidSettings>(builder.Configuration, "HashidSettings");

// --- LOAD DA CONFIG DE TENANT ---
builder.Services.AddValidatedSettings<TenantSettings>(builder.Configuration, "TenantSettings");

// --- LOAD DA CONFIG DE URLS ---
builder.Services.AddValidatedSettings<UrlSettings>(builder.Configuration, "UrlSettings");

// --- CONFIGURA��O DO REDIS ---
builder.Services.AddStackExchangeRedisCache(options =>
{
    options.Configuration = redisConfig;
    options.InstanceName = "Garius:";
});

// --- CONFIGURA��O DO BANCO DE DADOS ---
builder.Services.AddDbContext<ApplicationDbContext>(options =>
    options.UseNpgsql(connectionString, npgsqlOptionsAction: sqlOptions =>
    {
        sqlOptions.EnableRetryOnFailure(
            maxRetryCount: 5,
            maxRetryDelay: TimeSpan.FromSeconds(30),
            errorCodesToAdd: null);
    }));

// --- CONFIGURA��O DO USER IDENTITY ---
builder.Services
    .AddIdentity<ApplicationUser, ApplicationRole>(options =>
    {
        // Configura��es de senha
        options.Password.RequireDigit = true;
        options.Password.RequiredLength = 6;
        options.Password.RequireNonAlphanumeric = true;
        options.Password.RequireUppercase = true;
        options.Password.RequireLowercase = true;
        options.Password.RequiredUniqueChars = 1;

        // Configura��es de Lockout
        options.Lockout.DefaultLockoutTimeSpan = TimeSpan.FromMinutes(5);
        options.Lockout.MaxFailedAccessAttempts = 5;
        options.Lockout.AllowedForNewUsers = true;

        // Configura��es de usu�rio
        options.User.AllowedUserNameCharacters =
            "abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUVWXYZ0123456789-._@+";
        options.User.RequireUniqueEmail = true;

        // Configura��es de SignIn
        options.SignIn.RequireConfirmedAccount = true;
        options.SignIn.RequireConfirmedEmail = true;
        options.SignIn.RequireConfirmedPhoneNumber = false;
    })
    .AddEntityFrameworkStores<ApplicationDbContext>()
    .AddDefaultTokenProviders();

// --- CONFIGURA��O DOS COOKIES DE AUTENTICA��O ---
builder.Services.Configure<CookieAuthenticationOptions>(IdentityConstants.ExternalScheme, options =>
{
    options.Cookie.SameSite = SameSiteMode.None;
    options.Cookie.SecurePolicy = CookieSecurePolicy.Always;
    options.Cookie.HttpOnly = true;
});

builder.Services.ConfigureApplicationCookie(options =>
{
    options.LoginPath = "/api/v1/auth/login";
    options.AccessDeniedPath = "/api/v1/auth/access-denied";
    options.Cookie.HttpOnly = true;
    options.Cookie.SameSite = SameSiteMode.None;
    options.Cookie.SecurePolicy = CookieSecurePolicy.Always;
});

builder.Services.ConfigureExternalCookie(options =>
{
    options.Cookie.SameSite = SameSiteMode.None;
    options.Cookie.SecurePolicy = CookieSecurePolicy.Always;
});

builder.Services.AddAuthentication(options =>
{
    options.DefaultAuthenticateScheme = JwtBearerDefaults.AuthenticationScheme;
    options.DefaultChallengeScheme = JwtBearerDefaults.AuthenticationScheme;
})
.AddJwtBearer(options =>
{
    var jwtConfig = builder.Configuration.GetSection("JwtSettings").Get<JwtSettings>()!;
    options.RequireHttpsMetadata = !builder.Environment.IsDevelopment();
    options.SaveToken = true;
    options.TokenValidationParameters = new TokenValidationParameters
    {
        ValidateIssuer = true,
        ValidateAudience = true,
        ValidateLifetime = true,
        ValidateIssuerSigningKey = true,
        ValidIssuer = jwtConfig.Issuer,
        ValidAudience = jwtConfig.Audience,
        IssuerSigningKey = new SymmetricSecurityKey(Encoding.UTF8.GetBytes(jwtConfig.Secret)),
        ClockSkew = TimeSpan.Zero,
    };
})
.AddGoogle("Google", options =>
{
    var google = builder.Configuration.GetSection("GoogleExternalAuthSettings").Get<GoogleExternalAuthSettings>()!;
    options.CorrelationCookie.SameSite = SameSiteMode.None;
    options.CorrelationCookie.SecurePolicy = CookieSecurePolicy.Always;
    options.ClientId = google.ClientId;
    options.ClientSecret = google.ClientSecret;
    options.SaveTokens = true;
    options.CallbackPath = "/signin-google";
    options.Scope.Add("profile");
    options.Scope.Add("email");
})
.AddMicrosoftAccount("Microsoft", options =>
{
    var ms = builder.Configuration.GetSection("MicrosoftExternalAuthSettings").Get<MicrosoftExternalAuthSettings>()!;
    options.ClientId = ms.ClientId;
    options.ClientSecret = ms.ClientSecret;
    options.SaveTokens = true;
    options.CallbackPath = "/signin-microsoft";
    options.CorrelationCookie.SameSite = SameSiteMode.None;
    options.CorrelationCookie.SecurePolicy = CookieSecurePolicy.Always;
});

// --- CONFIGURA��O DO HEALTH CHECK ---
builder.Services.AddHealthChecks()
    .AddCheck<HealthCheckHelper>("config")
    .AddNpgSql(connectionString, name: "PostgreSQL",
               failureStatus: HealthStatus.Unhealthy,
               tags: new[] { "db" })
    .AddRedis(redisConfig, name: "Redis",
              failureStatus: HealthStatus.Unhealthy,
              tags: new[] { "cache" })
    .AddCheck("self", () => HealthCheckResult.Healthy("UP"));

// --- CONFIGURA��O DOS HEADERS DE SEGURAN�A ---
builder.Services.Configure<ForwardedHeadersOptions>(options =>
{
    options.ForwardedHeaders = ForwardedHeaders.XForwardedFor | ForwardedHeaders.XForwardedProto;
    options.KnownNetworks.Clear();
    options.KnownProxies.Clear();
});

// --- CONFIGURA��O DO DATA PROTECTION ---
var mux = ConnectionMultiplexer.Connect(redisConfig);
builder.Services
    .AddDataProtection()
    .SetApplicationName("Garius.Api")
    .SetDefaultKeyLifetime(TimeSpan.FromDays(90))
    .PersistKeysToStackExchangeRedis(mux, "DataProtection-Keys");

// --- CONFIGURA��O DOS CONTROLLERS ---
builder.Services.AddControllers()
    .ConfigureApiBehaviorOptions(options =>
    {
        options.SuppressModelStateInvalidFilter = true;
    })
    .AddJsonOptions(options =>
    {
        options.JsonSerializerOptions.PropertyNamingPolicy = JsonNamingPolicy.CamelCase;
        options.JsonSerializerOptions.DictionaryKeyPolicy = JsonNamingPolicy.CamelCase;
    });

// ###############################
// ### INJE��O DE DEPEND�NCIAS ###
// ###############################


// --- CONFIGURA��O DO AUTO MAPPER ---
builder.Services.AddAutoMapper(
    cfg => { },
    typeof(MappingProfile)
);
builder.Services.AddScoped<MapperService>();

// --- CONFIGURA��O DO TENANT SERVICE ---
builder.Services.AddScoped<ITenantService, TenantService>();

// --- CONFIGURA��O DO RESEND ---
builder.Services.AddHttpClient<IEmailSender, ResendEmailSender>();

// --- CONFIGURA��O DE SERVI�OS DE TOKEN ---
builder.Services.AddScoped<IJwtTokenGenerator, JwtTokenGenerator>();

// --- CONFIGURA��O DE SERVI�OS DE AUTENTICA��O ---
builder.Services.AddScoped<IAuthService, AuthService>();

// --- CONFIGURA��O DE SERVI�OS DE ROLES ---
builder.Services.AddScoped<IRoleService, RoleService>();

// --- CONFIGURA��O DE USU�RIOS ---
builder.Services.AddScoped<IUserService, UserService>();

// --- CONFIGURA��O DE SERVI�OS DE CUSTOMIZA��O DO AUTHORIZE ---
builder.Services.AddSingleton<IAuthorizationMiddlewareResultHandler, CustomAuthorizationMiddleware>();

// --- CONFIGURA��O DE SERVI�OS DO REDIS ---
builder.Services.AddSingleton<ICacheService, RedisCacheService>();

// --- CONFIGURA��O DO HELPER PARA COLETAR DADOS DE USU�RIO LOGADO ---
builder.Services.AddScoped<LoggedUserHelper>();

// --- CONFIGURA��O DOS SERVI�OS DE TENANT ---
builder.Services.AddScoped<ITenantManagementService, TenantManagementService>();

// --- CONFIGURA��O DO RESOLVER DE USU�RIO DO SISTEMA ---
builder.Services.AddScoped<ISystemUserResolver, SystemUserResolver>();

// --- CONFIGURA��O DO SERVI�O DE EMAIL TEMPLATE ---
builder.Services.AddScoped<IEmailTemplateService, EmailTemplateService>();

// --- CONFIGURA��O DO SERVI�O DE AUTH POLICY PROVIDER ---
builder.Services.AddSingleton<IAuthorizationPolicyProvider, PermissionPolicyProvider>();
builder.Services.AddScoped<IAuthorizationHandler, PermissionAuthorizationHandler>();

// --- CONFIGURA��O DO SERVI�O DE HASH ID ---
builder.Services.AddScoped<IHashIdService, HashIdService>();


var app = builder.Build();

// --- CONFIGURA��O DO LOG DE REQUISI��ES ---
app.UseSerilogRequestLogging(o =>
{
    o.EnrichDiagnosticContext = (d, ctx) =>
    {
        d.Set("RequestPath", ctx.Request.Path);
        d.Set("ClientIP", ctx.Connection.RemoteIpAddress?.ToString() ?? "UNKNOWN");
        d.Set("XForwardedFor", ctx.Request.Headers["X-Forwarded-For"].ToString());
        d.Set("CFConnectingIP", ctx.Request.Headers["CF-Connecting-IP"].ToString());
        d.Set("UserAgent", ctx.Request.Headers.UserAgent.ToString());
        d.Set("StatusCode", ctx.Response?.StatusCode ?? 0);
    };
});
// --- SEED DO BANCO DE DADOS ---


app.UseForwardedHeaders();

// --- CONFIGURA��O DA BUILD DE MIGRATION ---
if (migrateOnly)
{
    var rootConnectionString = connectionStringSettings.GetRootConnectionString(builder.Environment.IsDevelopment());

    await using (var conn = new Npgsql.NpgsqlConnection(rootConnectionString))
    {
        await conn.OpenAsync();
        var existsSql = "SELECT 1 FROM pg_database WHERE datname = @db";
        await using (var cmd = new Npgsql.NpgsqlCommand(existsSql, conn))
        {
            cmd.Parameters.AddWithValue("db", connectionStringSettings.Database);
            var exists = await cmd.ExecuteScalarAsync();

            if (exists == null)
            {
                Log.Information("Database {DbName} not found. Creating...", connectionStringSettings.Database);
                await using var createDb = new Npgsql.NpgsqlCommand($@"CREATE DATABASE ""{connectionStringSettings.Database}"";", conn);
                await createDb.ExecuteNonQueryAsync();
            }
            else
            {
                Log.Information("Database {DbName} already exists.", connectionStringSettings.Database);
            }
        }
    }

    using var scope = app.Services.CreateScope();
    var context = scope.ServiceProvider.GetRequiredService<ApplicationDbContext>();

    Log.Information("Running migrations...");
    await context.Database.MigrateAsync().ConfigureAwait(false);
    Log.Information("Migrations completed successfully.");

    var serviceProvider = scope.ServiceProvider;
    await ApplicationDbContextSeeder.SeedRolesAndPermissionsAsync(serviceProvider);

    await using (var conn = new Npgsql.NpgsqlConnection(connectionString))
    {
        await conn.OpenAsync();

        var sql = $@"
                -- CREATE USER IF NOT EXISTS {connectionStringSettings.users.Admin.Name} WITH PASSWORD 'C*aYQMuDqK2nBJBakP#f';

                DO
                $do$
                BEGIN
                   IF NOT EXISTS (SELECT FROM pg_catalog.pg_user WHERE usename = '{connectionStringSettings.users.Admin.Name}') THEN
                      CREATE USER {connectionStringSettings.users.Admin.Name} WITH PASSWORD '{connectionStringSettings.users.Admin.Pwd}';
                   END IF;
                END
                $do$;
                
                GRANT CONNECT ON DATABASE ""{connectionStringSettings.Database}"" TO {connectionStringSettings.users.Admin.Name};
                GRANT USAGE, CREATE ON SCHEMA public TO {connectionStringSettings.users.Admin.Name};
                GRANT ALL PRIVILEGES ON ALL TABLES IN SCHEMA public TO {connectionStringSettings.users.Admin.Name};
                GRANT ALL PRIVILEGES ON ALL SEQUENCES IN SCHEMA public TO {connectionStringSettings.users.Admin.Name};
                ALTER DEFAULT PRIVILEGES FOR USER {connectionStringSettings.users.Admin.Name} IN SCHEMA public
                GRANT ALL PRIVILEGES ON TABLES TO {connectionStringSettings.users.Admin.Name};
                ALTER DEFAULT PRIVILEGES FOR USER {connectionStringSettings.users.Admin.Name} IN SCHEMA public
                GRANT ALL PRIVILEGES ON SEQUENCES TO {connectionStringSettings.users.Admin.Name};

                -- Usu�rio para produ��o (execu��o da API)
                -- CREATE USER IF NOT EXISTS {connectionStringSettings.users.Common.Name} WITH PASSWORD 'g2FEzaR@8$Vp5SfVN@GVS^1KQ5X&rX78s4DVzDJ&';

                DO
                $do$
                BEGIN
                   IF NOT EXISTS (SELECT FROM pg_catalog.pg_user WHERE usename = '{connectionStringSettings.users.Common.Name}') THEN
                      CREATE USER {connectionStringSettings.users.Common.Name} WITH PASSWORD '{connectionStringSettings.users.Common.Pwd}';
                   END IF;
                END
                $do$;

                GRANT CONNECT ON DATABASE ""{connectionStringSettings.Database}"" TO {connectionStringSettings.users.Common.Name};
                GRANT USAGE ON SCHEMA public TO {connectionStringSettings.users.Common.Name};
                GRANT SELECT, INSERT, UPDATE, DELETE ON ALL TABLES IN SCHEMA public TO {connectionStringSettings.users.Common.Name};
                GRANT USAGE, SELECT, UPDATE ON ALL SEQUENCES IN SCHEMA public TO {connectionStringSettings.users.Common.Name};
                ALTER DEFAULT PRIVILEGES IN SCHEMA public
                GRANT SELECT, INSERT, UPDATE, DELETE ON TABLES TO {connectionStringSettings.users.Common.Name};
                ALTER DEFAULT PRIVILEGES IN SCHEMA public
                GRANT USAGE, SELECT, UPDATE ON SEQUENCES TO {connectionStringSettings.users.Common.Name};

                -- *** ESSENCIAL: Permiss�es para tabelas criadas pelo app_admin ***
                ALTER DEFAULT PRIVILEGES FOR USER {connectionStringSettings.users.Admin.Name} IN SCHEMA public
                GRANT SELECT, INSERT, UPDATE, DELETE ON TABLES TO {connectionStringSettings.users.Common.Name};
                ALTER DEFAULT PRIVILEGES FOR USER {connectionStringSettings.users.Admin.Name} IN SCHEMA public
                GRANT USAGE, SELECT, UPDATE ON SEQUENCES TO {connectionStringSettings.users.Common.Name};
            ";

        await using var cmd = new Npgsql.NpgsqlCommand(sql, conn);
        await cmd.ExecuteNonQueryAsync();
        Log.Information("Roles and permissions applied.");
    }

   

    //using (var scope = app.Services.CreateScope())
    //{
    //    var context = scope.ServiceProvider.GetRequiredService<ApplicationDbContext>();

    //    try
    //    {
    //        Log.Information("Running migrations...");
    //        await context.Database.MigrateAsync().ConfigureAwait(false);
    //        Log.Information("Migrations completed successfully.");
    //    }
    //    catch (Exception ex)
    //    {
    //        Log.Fatal($"Migration failed: {ex.Message}");
    //        Log.CloseAndFlush();
    //        Environment.Exit(1);
    //    }
    //}

    //using (var scope = app.Services.CreateScope())
    //{
    //    var serviceProvider = scope.ServiceProvider;
    //    try
    //    {
    //        await ApplicationDbContextSeeder.SeedRolesAndPermissionsAsync(serviceProvider);
    //    }
    //    catch (Exception ex)
    //    {
    //        var logger = serviceProvider.GetRequiredService<ILogger<Program>>();
    //        logger.LogError(ex, "An error occurred while seeding the database.");
    //    }
    //}

    Log.CloseAndFlush();
    Environment.Exit(0);
}

// --- CONFIGURA��O DO MIDDLEWARE DE TRATAMENTO DE EXCE��ES ---
app.UseMiddleware<ExceptionHandlingMiddleware>();

// --- CONFIGURA��O DO SWAGGER UI ---
var provider = app.Services.GetRequiredService<IApiVersionDescriptionProvider>();
if (app.Environment.IsDevelopment() || enableSwagger)
{
    app.UseSwagger();
    app.UseSwaggerUI(options =>
    {
        foreach (var description in provider.ApiVersionDescriptions)
        {
            options.SwaggerEndpoint($"/swagger/{description.GroupName}/swagger.json",
                $"GariusWeb.Api {description.GroupName.ToUpper(System.Globalization.CultureInfo.InvariantCulture)}");
        }

        options.RoutePrefix = "swagger";
        options.DefaultModelExpandDepth(-1);
    });
}

// --- CONFIGURA��O DOS ENDPOINTS DE DESENVOLVIMENTO ---
app.MapDevEndpoints();

// --- CONFIGURA��O DO PIPELINE DE REQUISI��ES ---
app.UseStaticFiles();
app.UseRouting();

app.UseRateLimiter();
app.UseCustomCors();

// --- HABILITA A REDIRECIONA DE HTTP PARA HTTPS ---
if (enableHttpsRedirect)
{
    app.UseHttpsRedirection();
}

// --- CONFIGURA��O DOS HEADERS DE SEGURAN�A ---
var corsOrigins = builder.Configuration
                         .GetSection("CorsSettings:AllowedOrigins")
                         .Get<string[]>() ?? Array.Empty<string>();

app.UseSecurityHeaders(policy =>
{
    policy.AddDefaultSecurityHeaders();
    policy.RemoveServerHeader();

    policy.AddReferrerPolicyNoReferrer();

    policy.AddPermissionsPolicy(builder =>
    {
        builder.AddGeolocation().None();
        builder.AddMicrophone().None();
        builder.AddCamera().None();
    });

    policy.AddContentSecurityPolicy(builder =>
    {
        builder.AddDefaultSrc().Self();
        builder.AddImgSrc().Self().From("data:");
        builder.AddFontSrc().Self();

        var connectSrcBuilder = builder.AddConnectSrc().Self();

        foreach (var origin in corsOrigins)
        {
            connectSrcBuilder.From(origin);
        }

        builder.AddScriptSrc().Self()
            .UnsafeInline()
            .From("https://*.stripe.com")
            .From("https://*.paypal.com")
            .From("https://*.google.com")
            .From("https://*.gstatic.com")
            .From("https://challenges.cloudflare.com");

        builder.AddStyleSrc().Self()
            .UnsafeInline()
            .From("https://*.stripe.com");

        builder.AddFrameSrc().Self()
            .From("https://*.stripe.com")
            .From("https://*.paypal.com")
            .From("https://*.google.com")
            .From("https://challenges.cloudflare.com");
    });
});

// --- CONFIGURA��O DA AUTENTICA��O E AUTORIZA��O ---
app.UseAuthentication();
app.UseAuthorization();

// --- CONFIGURA��O DOS CONTROLLERS ---
app.MapControllers();

// --- CRIA��O DO ENDPOINT DE HEALTH CHECK ---
app.MapHealthChecks("/health", new HealthCheckOptions { Predicate = _ => false });
app.MapHealthChecks("/healthz", new HealthCheckOptions
{
    Predicate = _ => true,
    ResponseWriter = async (context, report) =>
    {
        context.Response.ContentType = "application/json";
        var result = System.Text.Json.JsonSerializer.Serialize(new
        {
            status = report.Status.ToString(),
            details = report.Entries.Select(e => new
            {
                key = e.Key,
                status = e.Value.Status.ToString(),
                description = string.IsNullOrEmpty(e.Value.Description)
                    ? e.Value.Status switch
                    {
                        HealthStatus.Healthy => "UP",
                        HealthStatus.Unhealthy => "DOWN",
                        HealthStatus.Degraded => "DEGRADED",
                        _ => "UNKNOWN",
                    }
                    : e.Value.Description,
                data = e.Value.Data,
            }),
        });
        await context.Response.WriteAsync(result).ConfigureAwait(false);
    },
});

app.Run();