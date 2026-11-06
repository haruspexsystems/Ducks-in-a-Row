using System;
using Microsoft.EntityFrameworkCore.Migrations;

#nullable disable

namespace Certus.Core.Data.Migrations
{
    /// <inheritdoc />
    public partial class AddAdminAuditTrail : Migration
    {
        /// <inheritdoc />
        protected override void Up(MigrationBuilder migrationBuilder)
        {
            migrationBuilder.CreateTable(
                name: "AdminAuditEntries",
                columns: table => new
                {
                    Id = table.Column<int>(type: "INTEGER", nullable: false)
                        .Annotation("Sqlite:Autoincrement", true),
                    OccurredAt = table.Column<DateTime>(type: "TEXT", nullable: false),
                    Actor = table.Column<string>(type: "TEXT", maxLength: 256, nullable: false),
                    Action = table.Column<string>(type: "TEXT", maxLength: 100, nullable: false),
                    Target = table.Column<string>(type: "TEXT", maxLength: 500, nullable: true),
                    BeforeValue = table.Column<string>(type: "TEXT", maxLength: 4000, nullable: true),
                    AfterValue = table.Column<string>(type: "TEXT", maxLength: 4000, nullable: true)
                },
                constraints: table =>
                {
                    table.PrimaryKey("PK_AdminAuditEntries", x => x.Id);
                });

            migrationBuilder.CreateTable(
                name: "AdminSignInFailures",
                columns: table => new
                {
                    Id = table.Column<int>(type: "INTEGER", nullable: false)
                        .Annotation("Sqlite:Autoincrement", true),
                    SourceAddress = table.Column<string>(type: "TEXT", maxLength: 64, nullable: false),
                    StatusCode = table.Column<int>(type: "INTEGER", nullable: false),
                    BucketStart = table.Column<DateTime>(type: "TEXT", nullable: false),
                    Count = table.Column<int>(type: "INTEGER", nullable: false),
                    FirstAt = table.Column<DateTime>(type: "TEXT", nullable: false),
                    LastAt = table.Column<DateTime>(type: "TEXT", nullable: false)
                },
                constraints: table =>
                {
                    table.PrimaryKey("PK_AdminSignInFailures", x => x.Id);
                });

            migrationBuilder.CreateIndex(
                name: "IX_AdminAuditEntries_Actor",
                table: "AdminAuditEntries",
                column: "Actor");

            migrationBuilder.CreateIndex(
                name: "IX_AdminAuditEntries_OccurredAt",
                table: "AdminAuditEntries",
                column: "OccurredAt");

            migrationBuilder.CreateIndex(
                name: "IX_AdminSignInFailures_BucketStart",
                table: "AdminSignInFailures",
                column: "BucketStart");

            migrationBuilder.CreateIndex(
                name: "IX_AdminSignInFailures_SourceAddress_StatusCode_BucketStart",
                table: "AdminSignInFailures",
                columns: new[] { "SourceAddress", "StatusCode", "BucketStart" },
                unique: true);
        }

        /// <inheritdoc />
        protected override void Down(MigrationBuilder migrationBuilder)
        {
            migrationBuilder.DropTable(
                name: "AdminAuditEntries");

            migrationBuilder.DropTable(
                name: "AdminSignInFailures");
        }
    }
}
