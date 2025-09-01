namespace GariusWeb.Api.Domain.Constants
{
    public static class SystemRoles
    {
        public const string Developer = "Developer";
        public const string SuperAdmin = "SuperAdmin";
        public const string Owner = "Owner";
        public const string Admin = "Admin";
        public const string Basic = "User";

        public static readonly IReadOnlyList<string> SuperUserRoles = new List<string> { Owner, SuperAdmin, Developer };
    }
}
