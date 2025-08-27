using Microsoft.AspNetCore.Identity;

namespace GariusWeb.Api.Domain.Entities.Identity
{
    public class ApplicationUserClaim : IdentityUserClaim<Guid>
    {
        public virtual ApplicationUser User { get; set; }
    }
}
