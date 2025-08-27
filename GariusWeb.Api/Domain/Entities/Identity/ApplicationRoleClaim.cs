using Microsoft.AspNetCore.Identity;

namespace GariusWeb.Api.Domain.Entities.Identity
{
    public class ApplicationRoleClaim : IdentityRoleClaim<Guid>
    {
        public virtual ApplicationRole Role { get; set; }
    }
}
