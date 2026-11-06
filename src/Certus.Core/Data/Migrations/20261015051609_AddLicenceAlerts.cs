using System;
using Microsoft.EntityFrameworkCore.Migrations;

#nullable disable

namespace Certus.Core.Data.Migrations
{
    /// <inheritdoc />
    public partial class AddLicenceAlerts : Migration
    {
        /// <inheritdoc />
        protected override void Up(MigrationBuilder migrationBuilder)
        {
            migrationBuilder.CreateTable(
                name: "LicenceAlertsSent",
                columns: table => new
                {
                    Id = table.Column<int>(type: "INTEGER", nullable: false)
                        .Annotation("Sqlite:Autoincrement", true),
                    LicenceId = table.Column<string>(type: "TEXT", maxLength: 36, nullable: false),
                    Stage = table.Column<string>(type: "TEXT", maxLength: 20, nullable: false),
                    SentAt = table.Column<DateTime>(type: "TEXT", nullable: false),
                    Channels = table.Column<string>(type: "TEXT", maxLength: 50, nullable: false),
                    Success = table.Column<bool>(type: "INTEGER", nullable: false)
                },
                constraints: table =>
                {
                    table.PrimaryKey("PK_LicenceAlertsSent", x => x.Id);
                });

            migrationBuilder.CreateIndex(
                name: "IX_LicenceAlertsSent_LicenceId_Stage",
                table: "LicenceAlertsSent",
                columns: new[] { "LicenceId", "Stage" },
                unique: true);

            migrationBuilder.CreateIndex(
                name: "IX_LicenceAlertsSent_SentAt",
                table: "LicenceAlertsSent",
                column: "SentAt");
        }

        /// <inheritdoc />
        protected override void Down(MigrationBuilder migrationBuilder)
        {
            migrationBuilder.DropTable(
                name: "LicenceAlertsSent");
        }
    }
}
