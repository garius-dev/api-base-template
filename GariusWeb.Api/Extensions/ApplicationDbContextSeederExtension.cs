namespace GariusWeb.Api.Extensions
{
    public static class ApplicationDbContextSeederExtension
    {
        public static async Task SeedRolesAndPermissionsAsync(IServiceProvider services, string environmentName)
        {
            var logger = services.GetRequiredService<ILoggerFactory>().CreateLogger("ApplicationDbContextSeeder");
            var config = services.GetRequiredService<IConfiguration>();

            string? connectionString = config[$"ConnectionStringSettings:{environmentName}"];

            string? databaseName = config[$"DatabaseSettings:Name"];

            string? adminUserName = config[$"DatabaseUserSettings:Admin:Name"];
            string? adminUserPwd = config[$"DatabaseUserSettings:Admin:Pwd"];
                
            string? commonUserName = config[$"DatabaseUserSettings:Common:Name"];
            string? commonUserPwd = config[$"DatabaseUserSettings:Common:Pwd"];
        }
    }
}
