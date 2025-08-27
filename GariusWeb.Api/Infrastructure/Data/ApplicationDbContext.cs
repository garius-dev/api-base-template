using GariusWeb.Api.Application.Interfaces;
using GariusWeb.Api.Domain.Abstractions.Interfaces;
using GariusWeb.Api.Domain.Entities;
using GariusWeb.Api.Domain.Entities.Identity;
using GariusWeb.Api.Domain.Entities.ServiceAccount;
using Microsoft.AspNetCore.Identity;
using Microsoft.AspNetCore.Identity.EntityFrameworkCore;
using Microsoft.EntityFrameworkCore;
using System.Linq.Expressions;
using System.Reflection.Emit;

namespace GariusWeb.Api.Infrastructure.Data
{
    public class ApplicationDbContext : IdentityDbContext<
        ApplicationUser, 
        ApplicationRole, 
        Guid,
        ApplicationUserClaim,
        ApplicationUserRole,
        IdentityUserLogin<Guid>,
        ApplicationRoleClaim,
        IdentityUserToken<Guid>>
    {
        // #####################################
        // #### Custom Entities Declaration ####
        // #####################################

        private readonly ITenantService _tenantService;
        public DbSet<ServiceAccountEntity> ServiceAccounts { get; set; }
        public DbSet<Tenant> Tenants { get; set; }
        public DbSet<Invitation> Invitations { get; set; }

        public ApplicationDbContext(DbContextOptions<ApplicationDbContext> options, ITenantService tenantService) : base(options)
        {
            _tenantService = tenantService;
        }

        protected override void OnModelCreating(ModelBuilder builder)
        {
            base.OnModelCreating(builder);

            foreach (var entityType in builder.Model.GetEntityTypes())
            {
                if (typeof(ITenantEntity).IsAssignableFrom(entityType.ClrType))
                {
                    var parameter = Expression.Parameter(entityType.ClrType, "e");
                    var property = Expression.Property(parameter, nameof(ITenantEntity.TenantId));
                    var tenantId = Expression.Constant(_tenantService.GetTenantId());
                    var body = Expression.Equal(property, tenantId);
                    var lambda = Expression.Lambda(body, parameter);

                    builder.Entity(entityType.ClrType).HasQueryFilter(lambda);
                }
            }


            builder.Entity<ApplicationRole>(b =>
            {
                b.HasMany(r => r.UserRoles)
                 .WithOne(ur => ur.Role)
                 .HasForeignKey(ur => ur.RoleId);
            });

            builder.Entity<ApplicationUserClaim>()
                .HasOne(c => c.User)
                .WithMany(u => u.Claims)
                .HasForeignKey(c => c.UserId);

            builder.Entity<ApplicationRoleClaim>()
                .HasOne(rc => rc.Role)
                .WithMany(r => r.Claims)
                .HasForeignKey(rc => rc.RoleId);

            builder.Entity<ApplicationUser>(e =>
            {
                e.HasIndex(u => u.NormalizedUserName).HasDatabaseName("UserNameIndex").IsUnique(false);
                e.HasIndex(u => new { u.TenantId, u.NormalizedUserName }).HasDatabaseName("IX_Tenant_UserName").IsUnique();

                e.HasMany(u => u.UserRoles)
                 .WithOne(ur => ur.User)
                 .HasForeignKey(ur => ur.UserId);

                e.Property(u => u.EmailSearch)
                 .HasComputedColumnSql(
                    "regexp_replace(lower(coalesce(\"Email\",'')), '[@._+-]', ' ', 'g')",
                    stored: true);

                e.HasGeneratedTsVectorColumn(
                     u => u.SearchVector,
                     "simple_unaccent",
                     u => new { u.FullName, u.UserName, u.EmailSearch }
                 );

                e.HasIndex(u => u.SearchVector).HasMethod("GIN");
                e.HasIndex(u => u.Email).HasMethod("GIN").HasOperators("gin_trgm_ops");
            });

            builder.Entity<ApplicationUser>()
            .HasGeneratedTsVectorColumn(
                u => u.SearchVector,
                "simple",
                u => new
                {
                    u.UserName,
                    u.Email,
                    u.FullName,
                }
            )
            .HasIndex(u => u.SearchVector)
            .HasMethod("GIN");

            // #######################################
            // #### Custom Entities Configuration ####
            // #######################################

            builder.Entity<Tenant>(e =>
            {
                // Mapeia a entidade Tenant para a tabela AspNetTenants
                e.ToTable("AspNetTenants");
            });

            builder.Entity<Invitation>(e =>
            {
                // Mapeia a entidade Invitation para a tabela AspNetInvitations
                e.ToTable("AspNetInvitations");
            });

            builder.Entity<ServiceAccountEntity>()
                .HasIndex(sa => sa.ClientId)
                .IsUnique();
        }
    }
}