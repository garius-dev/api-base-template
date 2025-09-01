namespace GariusWeb.Api.Domain.Constants
{
    public static class Permissions
    {
        public static class Tenants
        {
            public const string Read = "Permissions.Tenants.Read";
            public const string Create = "Permissions.Tenants.Create";
            public const string Update = "Permissions.Tenants.Update";
            public const string Delete = "Permissions.Tenants.Delete";
            public const string Manage = "Permissions.Tenants.Manage";
        }

        public static class Accounts
        {
            public const string Read = "Permissions.Accounts.Read";
            public const string Manage = "Permissions.Accounts.Manage";
        }

        public static class Roles
        {
            public const string Read = "Permissions.Roles.Read";
            public const string Create = "Permissions.Roles.Create";
            public const string Update = "Permissions.Roles.Update";
            public const string Delete = "Permissions.Roles.Delete";
            public const string Manage = "Permissions.Roles.Manage";
        }

        /// <summary>
        /// Retorna uma lista de todas as constantes de permissão definidas na classe.
        /// </summary>
        /// <returns>Uma lista de strings de permissão.</returns>
        public static List<string> GetAllPermissions()
        {
            var allPermissions = new List<string>();
            var nestedTypes = typeof(Permissions).GetNestedTypes();

            foreach (var type in nestedTypes)
            {
                var fields = type.GetFields(System.Reflection.BindingFlags.Public | System.Reflection.BindingFlags.Static | System.Reflection.BindingFlags.FlattenHierarchy);
                allPermissions.AddRange(fields.Select(fi => fi.GetValue(null)?.ToString() ?? string.Empty));
            }

            return allPermissions.Where(p => !string.IsNullOrEmpty(p)).Distinct().ToList();
        }
    }
}
