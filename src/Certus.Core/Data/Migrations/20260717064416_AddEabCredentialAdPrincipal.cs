using Microsoft.EntityFrameworkCore.Migrations;

#nullable disable

namespace Certus.Core.Data.Migrations
{
    /// <inheritdoc />
    public partial class AddEabCredentialAdPrincipal : Migration
    {
        /// <inheritdoc />
        protected override void Up(MigrationBuilder migrationBuilder)
        {
            migrationBuilder.AddColumn<string>(
                name: "AdPrincipalName",
                table: "EabCredentials",
                type: "TEXT",
                maxLength: 256,
                nullable: true);

            migrationBuilder.AddColumn<string>(
                name: "AdPrincipalSid",
                table: "EabCredentials",
                type: "TEXT",
                maxLength: 128,
                nullable: true);

            migrationBuilder.AddColumn<string>(
                name: "AdPrincipalType",
                table: "EabCredentials",
                type: "TEXT",
                maxLength: 20,
                nullable: true);
        }

        /// <inheritdoc />
        protected override void Down(MigrationBuilder migrationBuilder)
        {
            migrationBuilder.DropColumn(
                name: "AdPrincipalName",
                table: "EabCredentials");

            migrationBuilder.DropColumn(
                name: "AdPrincipalSid",
                table: "EabCredentials");

            migrationBuilder.DropColumn(
                name: "AdPrincipalType",
                table: "EabCredentials");
        }
    }
}
