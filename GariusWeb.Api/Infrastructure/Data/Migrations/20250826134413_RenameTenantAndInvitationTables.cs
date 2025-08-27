using Microsoft.EntityFrameworkCore.Migrations;

#nullable disable

namespace GariusWeb.Api.Infrastructure.Data.Migrations
{
    /// <inheritdoc />
    public partial class RenameTenantAndInvitationTables : Migration
    {
        /// <inheritdoc />
        protected override void Up(MigrationBuilder migrationBuilder)
        {
            migrationBuilder.DropForeignKey(
                name: "FK_AspNetUsers_Tenants_TenantId",
                table: "AspNetUsers");

            migrationBuilder.DropForeignKey(
                name: "FK_Invitations_AspNetUsers_InvitedByUserId",
                table: "Invitations");

            migrationBuilder.DropForeignKey(
                name: "FK_Invitations_Tenants_TenantId",
                table: "Invitations");

            migrationBuilder.DropPrimaryKey(
                name: "PK_Tenants",
                table: "Tenants");

            migrationBuilder.DropPrimaryKey(
                name: "PK_Invitations",
                table: "Invitations");

            migrationBuilder.RenameTable(
                name: "Tenants",
                newName: "AspNetTenants");

            migrationBuilder.RenameTable(
                name: "Invitations",
                newName: "AspNetInvitations");

            migrationBuilder.RenameIndex(
                name: "IX_Invitations_TenantId",
                table: "AspNetInvitations",
                newName: "IX_AspNetInvitations_TenantId");

            migrationBuilder.RenameIndex(
                name: "IX_Invitations_InvitedByUserId",
                table: "AspNetInvitations",
                newName: "IX_AspNetInvitations_InvitedByUserId");

            migrationBuilder.AddPrimaryKey(
                name: "PK_AspNetTenants",
                table: "AspNetTenants",
                column: "Id");

            migrationBuilder.AddPrimaryKey(
                name: "PK_AspNetInvitations",
                table: "AspNetInvitations",
                column: "Id");

            migrationBuilder.AddForeignKey(
                name: "FK_AspNetInvitations_AspNetTenants_TenantId",
                table: "AspNetInvitations",
                column: "TenantId",
                principalTable: "AspNetTenants",
                principalColumn: "Id",
                onDelete: ReferentialAction.Cascade);

            migrationBuilder.AddForeignKey(
                name: "FK_AspNetInvitations_AspNetUsers_InvitedByUserId",
                table: "AspNetInvitations",
                column: "InvitedByUserId",
                principalTable: "AspNetUsers",
                principalColumn: "Id",
                onDelete: ReferentialAction.Cascade);

            migrationBuilder.AddForeignKey(
                name: "FK_AspNetUsers_AspNetTenants_TenantId",
                table: "AspNetUsers",
                column: "TenantId",
                principalTable: "AspNetTenants",
                principalColumn: "Id",
                onDelete: ReferentialAction.Cascade);
        }

        /// <inheritdoc />
        protected override void Down(MigrationBuilder migrationBuilder)
        {
            migrationBuilder.DropForeignKey(
                name: "FK_AspNetInvitations_AspNetTenants_TenantId",
                table: "AspNetInvitations");

            migrationBuilder.DropForeignKey(
                name: "FK_AspNetInvitations_AspNetUsers_InvitedByUserId",
                table: "AspNetInvitations");

            migrationBuilder.DropForeignKey(
                name: "FK_AspNetUsers_AspNetTenants_TenantId",
                table: "AspNetUsers");

            migrationBuilder.DropPrimaryKey(
                name: "PK_AspNetTenants",
                table: "AspNetTenants");

            migrationBuilder.DropPrimaryKey(
                name: "PK_AspNetInvitations",
                table: "AspNetInvitations");

            migrationBuilder.RenameTable(
                name: "AspNetTenants",
                newName: "Tenants");

            migrationBuilder.RenameTable(
                name: "AspNetInvitations",
                newName: "Invitations");

            migrationBuilder.RenameIndex(
                name: "IX_AspNetInvitations_TenantId",
                table: "Invitations",
                newName: "IX_Invitations_TenantId");

            migrationBuilder.RenameIndex(
                name: "IX_AspNetInvitations_InvitedByUserId",
                table: "Invitations",
                newName: "IX_Invitations_InvitedByUserId");

            migrationBuilder.AddPrimaryKey(
                name: "PK_Tenants",
                table: "Tenants",
                column: "Id");

            migrationBuilder.AddPrimaryKey(
                name: "PK_Invitations",
                table: "Invitations",
                column: "Id");

            migrationBuilder.AddForeignKey(
                name: "FK_AspNetUsers_Tenants_TenantId",
                table: "AspNetUsers",
                column: "TenantId",
                principalTable: "Tenants",
                principalColumn: "Id",
                onDelete: ReferentialAction.Cascade);

            migrationBuilder.AddForeignKey(
                name: "FK_Invitations_AspNetUsers_InvitedByUserId",
                table: "Invitations",
                column: "InvitedByUserId",
                principalTable: "AspNetUsers",
                principalColumn: "Id",
                onDelete: ReferentialAction.Cascade);

            migrationBuilder.AddForeignKey(
                name: "FK_Invitations_Tenants_TenantId",
                table: "Invitations",
                column: "TenantId",
                principalTable: "Tenants",
                principalColumn: "Id",
                onDelete: ReferentialAction.Cascade);
        }
    }
}
