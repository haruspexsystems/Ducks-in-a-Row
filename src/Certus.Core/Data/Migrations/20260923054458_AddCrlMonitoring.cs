using System;
using Microsoft.EntityFrameworkCore.Migrations;

#nullable disable

namespace Certus.Core.Data.Migrations
{
    /// <inheritdoc />
    public partial class AddCrlMonitoring : Migration
    {
        /// <inheritdoc />
        protected override void Up(MigrationBuilder migrationBuilder)
        {
            migrationBuilder.CreateTable(
                name: "CrlAlertsSent",
                columns: table => new
                {
                    Id = table.Column<int>(type: "INTEGER", nullable: false)
                        .Annotation("Sqlite:Autoincrement", true),
                    IssuerKeyId = table.Column<string>(type: "TEXT", maxLength: 64, nullable: false),
                    Kind = table.Column<string>(type: "TEXT", maxLength: 10, nullable: false),
                    InstanceKey = table.Column<string>(type: "TEXT", maxLength: 64, nullable: false),
                    Stage = table.Column<string>(type: "TEXT", maxLength: 20, nullable: false),
                    IssuerName = table.Column<string>(type: "TEXT", maxLength: 512, nullable: false),
                    NextUpdate = table.Column<DateTime>(type: "TEXT", nullable: true),
                    SentAt = table.Column<DateTime>(type: "TEXT", nullable: false),
                    Channels = table.Column<string>(type: "TEXT", maxLength: 50, nullable: false),
                    Success = table.Column<bool>(type: "INTEGER", nullable: false),
                    ErrorMessage = table.Column<string>(type: "TEXT", maxLength: 1000, nullable: true)
                },
                constraints: table =>
                {
                    table.PrimaryKey("PK_CrlAlertsSent", x => x.Id);
                });

            migrationBuilder.CreateTable(
                name: "MonitoredCrls",
                columns: table => new
                {
                    Id = table.Column<int>(type: "INTEGER", nullable: false)
                        .Annotation("Sqlite:Autoincrement", true),
                    Scope = table.Column<string>(type: "TEXT", maxLength: 10, nullable: false),
                    IssuerKeyId = table.Column<string>(type: "TEXT", maxLength: 64, nullable: false),
                    IssuerName = table.Column<string>(type: "TEXT", maxLength: 512, nullable: false),
                    Kind = table.Column<string>(type: "TEXT", maxLength: 10, nullable: false),
                    Source = table.Column<string>(type: "TEXT", maxLength: 512, nullable: false),
                    CrlNumber = table.Column<string>(type: "TEXT", maxLength: 64, nullable: true),
                    InstanceKey = table.Column<string>(type: "TEXT", maxLength: 64, nullable: true),
                    ThisUpdate = table.Column<DateTime>(type: "TEXT", nullable: true),
                    NextUpdate = table.Column<DateTime>(type: "TEXT", nullable: true),
                    NextPublish = table.Column<DateTime>(type: "TEXT", nullable: true),
                    AutoPublished = table.Column<bool>(type: "INTEGER", nullable: false),
                    SignatureStatus = table.Column<string>(type: "TEXT", maxLength: 20, nullable: true),
                    PublishFlags = table.Column<int>(type: "INTEGER", nullable: true),
                    LastCheckedAt = table.Column<DateTime>(type: "TEXT", nullable: false),
                    LastReadAt = table.Column<DateTime>(type: "TEXT", nullable: true),
                    LastError = table.Column<string>(type: "TEXT", maxLength: 500, nullable: true),
                    ETag = table.Column<string>(type: "TEXT", maxLength: 200, nullable: true),
                    LastModified = table.Column<DateTime>(type: "TEXT", nullable: true)
                },
                constraints: table =>
                {
                    table.PrimaryKey("PK_MonitoredCrls", x => x.Id);
                });

            migrationBuilder.CreateIndex(
                name: "IX_CrlAlertsSent_IssuerKeyId_Kind_InstanceKey_Stage",
                table: "CrlAlertsSent",
                columns: new[] { "IssuerKeyId", "Kind", "InstanceKey", "Stage" },
                unique: true);

            migrationBuilder.CreateIndex(
                name: "IX_CrlAlertsSent_SentAt",
                table: "CrlAlertsSent",
                column: "SentAt");

            migrationBuilder.CreateIndex(
                name: "IX_MonitoredCrls_Scope_IssuerKeyId_Kind_Source",
                table: "MonitoredCrls",
                columns: new[] { "Scope", "IssuerKeyId", "Kind", "Source" },
                unique: true);
        }

        /// <inheritdoc />
        protected override void Down(MigrationBuilder migrationBuilder)
        {
            migrationBuilder.DropTable(
                name: "CrlAlertsSent");

            migrationBuilder.DropTable(
                name: "MonitoredCrls");
        }
    }
}
