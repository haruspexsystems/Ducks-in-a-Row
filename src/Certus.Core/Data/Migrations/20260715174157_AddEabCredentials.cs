using System;
using Microsoft.EntityFrameworkCore.Migrations;

#nullable disable

namespace Certus.Core.Data.Migrations
{
    /// <inheritdoc />
    public partial class AddEabCredentials : Migration
    {
        /// <inheritdoc />
        protected override void Up(MigrationBuilder migrationBuilder)
        {
            migrationBuilder.AddColumn<string>(
                name: "EabJwsJson",
                table: "AcmeAccounts",
                type: "TEXT",
                nullable: true);

            migrationBuilder.AddColumn<int>(
                name: "ExternalAccountCredentialId",
                table: "AcmeAccounts",
                type: "INTEGER",
                nullable: true);

            migrationBuilder.CreateTable(
                name: "EabCredentials",
                columns: table => new
                {
                    Id = table.Column<int>(type: "INTEGER", nullable: false)
                        .Annotation("Sqlite:Autoincrement", true),
                    KeyId = table.Column<string>(type: "TEXT", maxLength: 64, nullable: false),
                    Name = table.Column<string>(type: "TEXT", maxLength: 200, nullable: false),
                    SecretProtected = table.Column<string>(type: "TEXT", nullable: false),
                    Status = table.Column<string>(type: "TEXT", maxLength: 20, nullable: false, defaultValue: "active"),
                    ExpiresAt = table.Column<DateTime>(type: "TEXT", nullable: true),
                    NamespacesJson = table.Column<string>(type: "TEXT", nullable: false, defaultValue: "[]"),
                    CreatedAt = table.Column<DateTime>(type: "TEXT", nullable: false),
                    UpdatedAt = table.Column<DateTime>(type: "TEXT", nullable: true),
                    RevokedAt = table.Column<DateTime>(type: "TEXT", nullable: true),
                    SecretRegeneratedAt = table.Column<DateTime>(type: "TEXT", nullable: true)
                },
                constraints: table =>
                {
                    table.PrimaryKey("PK_EabCredentials", x => x.Id);
                });

            migrationBuilder.CreateIndex(
                name: "IX_AcmeAccounts_ExternalAccountCredentialId",
                table: "AcmeAccounts",
                column: "ExternalAccountCredentialId");

            migrationBuilder.CreateIndex(
                name: "IX_EabCredentials_KeyId",
                table: "EabCredentials",
                column: "KeyId",
                unique: true);

            migrationBuilder.AddForeignKey(
                name: "FK_AcmeAccounts_EabCredentials_ExternalAccountCredentialId",
                table: "AcmeAccounts",
                column: "ExternalAccountCredentialId",
                principalTable: "EabCredentials",
                principalColumn: "Id",
                onDelete: ReferentialAction.Restrict);
        }

        /// <inheritdoc />
        protected override void Down(MigrationBuilder migrationBuilder)
        {
            migrationBuilder.DropForeignKey(
                name: "FK_AcmeAccounts_EabCredentials_ExternalAccountCredentialId",
                table: "AcmeAccounts");

            migrationBuilder.DropTable(
                name: "EabCredentials");

            migrationBuilder.DropIndex(
                name: "IX_AcmeAccounts_ExternalAccountCredentialId",
                table: "AcmeAccounts");

            migrationBuilder.DropColumn(
                name: "EabJwsJson",
                table: "AcmeAccounts");

            migrationBuilder.DropColumn(
                name: "ExternalAccountCredentialId",
                table: "AcmeAccounts");
        }
    }
}
