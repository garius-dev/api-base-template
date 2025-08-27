using GariusWeb.Api.Application.Exceptions;
using GariusWeb.Api.Application.Interfaces;
using GariusWeb.Api.Application.Services;
using GariusWeb.Api.Domain.Entities.Identity;
using GariusWeb.Api.Helpers;
using Microsoft.AspNetCore.Identity;
using Microsoft.Extensions.Caching.Distributed;
using System.Security.Claims;

namespace GariusWeb.Api.WebApi.Dev
{
    public static class DevEndpointExtensions
    {
        public static IEndpointRouteBuilder MapDevEndpoints(this IEndpointRouteBuilder app)
        {
            var env = app.ServiceProvider.GetRequiredService<IHostEnvironment>();

            var cfg = app.ServiceProvider.GetRequiredService<IConfiguration>();
            var enabled = cfg.GetValue("DEV_ENDPOINTS_ENABLED", true);

            if (!env.IsDevelopment())
            {
                if (!enabled)
                {
                    return app;
                }
            }

            var group = app.MapGroup("/dev")
                       .WithTags("Dev");

            // --- CRIAÇÃO DO ENDPOINT DE TESTE DE PING DO REDIS ---
            group.MapGet("/redis/ping", async (IDistributedCache cache) =>
            {
                const string key = "cache-teste";
                var valor = await cache.GetStringAsync(key).ConfigureAwait(false);

                if (valor != null)
                    return Results.Ok(new { valor, deCache = true });

                valor = $"Gerado em {DateTime.Now}";
                await cache.SetStringAsync(key, valor, new DistributedCacheEntryOptions
                {
                    AbsoluteExpirationRelativeToNow = TimeSpan.FromSeconds(30),
                }).ConfigureAwait(false);

                return Results.Ok(new { valor, deCache = false });
            });

            group.MapPost("/seed/developer", async (
                HttpRequest http,
                UserManager<ApplicationUser> users,
                RoleManager<ApplicationRole> roles,
                IJwtTokenGenerator jwtGenerator,
                ITenantService tenantService) =>
            {
                var email = http.Query["email"].ToString();
                var username = http.Query["username"].ToString();
                var password = http.Query["password"].ToString();

                if (string.IsNullOrWhiteSpace(email)) email = "dev.tester@example.local";
                if (string.IsNullOrWhiteSpace(username)) username = "dev.tester";
                if (string.IsNullOrWhiteSpace(password)) password = "Dev!12345";

                var devRoleName = GetDeveloperRoleName();

                if (!await roles.RoleExistsAsync(devRoleName).ConfigureAwait(false))
                {
                    var roleCreate = await roles.CreateAsync(new ApplicationRole
                    {
                        Id = Guid.NewGuid(),
                        Name = devRoleName,
                        NormalizedName = devRoleName.ToUpperInvariant(),
                    }).ConfigureAwait(false);

                    if (!roleCreate.Succeeded)
                    {
                        throw new BadRequestException("Falha ao criar role Developer");
                    }
                }

                var user = await users.FindByEmailAsync(email).ConfigureAwait(false);
                if (user is null)
                {
                    user = new ApplicationUser
                    {
                        Id = Guid.NewGuid(),
                        FirstName = "Dev",
                        LastName = "Tester",
                        Email = email,
                        UserName = username,
                        EmailConfirmed = true,
                        PhoneNumberConfirmed = true,
                        LockoutEnabled = false,
                        TenantId = tenantService.GetTenantId()
                    };
                    user.FullName = $"{user.FirstName} {user.LastName}";
                    user.NormalizedFullName = user.FullName.ToUpperInvariant();

                    var create = await users.CreateAsync(user, password).ConfigureAwait(false);

                    if (!create.Succeeded)
                    {
                        throw new BadRequestException("Falha ao criar usuário de teste.");
                    }
                }

                if (!await users.IsInRoleAsync(user, devRoleName).ConfigureAwait(false))
                {
                    var addRole = await users.AddToRoleAsync(user, devRoleName).ConfigureAwait(false);
                    if (!addRole.Succeeded)
                    {
                        throw new BadRequestException("Falha ao adicionar role Developer.");
                    }
                }

                string token;

                var extraClaims = new List<Claim>
                {
                    new("dev-seed", "true"),
                };

                token = jwtGenerator.GenerateToken(user, new List<string> { devRoleName }, extraClaims);

                return Results.Ok(ApiResponse<string>.Ok(token, "Sucesso!"));
            });

            group.MapDelete("/seed/developer", async (
                HttpRequest http,
                UserManager<ApplicationUser> users) =>
            {
                var email = http.Query["email"].ToString();
                if (string.IsNullOrWhiteSpace(email)) email = "dev.tester@example.local";

                var user = await users.FindByEmailAsync(email).ConfigureAwait(false);
                if (user is null)
                    return Results.Ok(ApiResponse<string>.Ok("Usuário não existe (ok)."));

                var del = await users.DeleteAsync(user).ConfigureAwait(false);
                if (!del.Succeeded)
                {
                    throw new BadRequestException("Falha ao remover o usuário de teste.");
                }

                return Results.Ok(ApiResponse<string>.Ok("Usuário de teste removido."));
            });

            return app;
        }

        private static string GetDeveloperRoleName()
        {
            return "Developer";
        }
    }
}