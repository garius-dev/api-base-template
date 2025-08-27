using Microsoft.EntityFrameworkCore.Migrations;

#nullable disable

namespace GariusWeb.Api.Infrastructure.Data.Migrations
{
    /// <inheritdoc />
    public partial class AddDummyFieldToTenant : Migration
    {
        /// <inheritdoc />
        protected override void Up(MigrationBuilder migrationBuilder)
        {
            migrationBuilder.AddColumn<bool>(
                name: "IsDummy",
                table: "Tenants",
                type: "boolean",
                nullable: false,
                defaultValue: false);
        }

        /// <inheritdoc />
        protected override void Down(MigrationBuilder migrationBuilder)
        {
            migrationBuilder.DropColumn(
                name: "IsDummy",
                table: "Tenants");
        }
    }
}
