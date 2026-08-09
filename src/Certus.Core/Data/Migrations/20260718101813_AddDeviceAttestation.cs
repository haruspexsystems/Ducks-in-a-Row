using System;
using Microsoft.EntityFrameworkCore.Migrations;

#nullable disable

namespace Certus.Core.Data.Migrations
{
    /// <inheritdoc />
    public partial class AddDeviceAttestation : Migration
    {
        /// <inheritdoc />
        protected override void Up(MigrationBuilder migrationBuilder)
        {
            migrationBuilder.AddColumn<string>(
                name: "AttestationObject",
                table: "AcmeChallenges",
                type: "TEXT",
                nullable: true);

            migrationBuilder.AddColumn<string>(
                name: "AttestationFormat",
                table: "AcmeAuthorizations",
                type: "TEXT",
                maxLength: 32,
                nullable: true);

            migrationBuilder.AddColumn<string>(
                name: "AttestedPropertiesJson",
                table: "AcmeAuthorizations",
                type: "TEXT",
                nullable: true);

            migrationBuilder.AddColumn<string>(
                name: "AttestedSpki",
                table: "AcmeAuthorizations",
                type: "TEXT",
                nullable: true);

            migrationBuilder.CreateTable(
                name: "AttestationTrustAnchors",
                columns: table => new
                {
                    Id = table.Column<int>(type: "INTEGER", nullable: false)
                        .Annotation("Sqlite:Autoincrement", true),
                    Format = table.Column<string>(type: "TEXT", maxLength: 32, nullable: false),
                    Name = table.Column<string>(type: "TEXT", maxLength: 200, nullable: false),
                    CertificatePem = table.Column<string>(type: "TEXT", nullable: false),
                    Sha256Fingerprint = table.Column<string>(type: "TEXT", maxLength: 64, nullable: false),
                    Enabled = table.Column<bool>(type: "INTEGER", nullable: false),
                    CreatedAt = table.Column<DateTime>(type: "TEXT", nullable: false)
                },
                constraints: table =>
                {
                    table.PrimaryKey("PK_AttestationTrustAnchors", x => x.Id);
                });

            migrationBuilder.CreateTable(
                name: "DeviceAttestationProfiles",
                columns: table => new
                {
                    Id = table.Column<int>(type: "INTEGER", nullable: false)
                        .Annotation("Sqlite:Autoincrement", true),
                    TemplateId = table.Column<string>(type: "TEXT", maxLength: 200, nullable: false),
                    Enabled = table.Column<bool>(type: "INTEGER", nullable: false),
                    GateMode = table.Column<string>(type: "TEXT", maxLength: 20, nullable: false, defaultValue: "allowlist"),
                    CsrIdentifierBinding = table.Column<string>(type: "TEXT", maxLength: 20, nullable: false, defaultValue: "cn-or-san"),
                    CreatedAt = table.Column<DateTime>(type: "TEXT", nullable: false),
                    UpdatedAt = table.Column<DateTime>(type: "TEXT", nullable: true)
                },
                constraints: table =>
                {
                    table.PrimaryKey("PK_DeviceAttestationProfiles", x => x.Id);
                });

            migrationBuilder.CreateTable(
                name: "DeviceAllowlistEntries",
                columns: table => new
                {
                    Id = table.Column<int>(type: "INTEGER", nullable: false)
                        .Annotation("Sqlite:Autoincrement", true),
                    ProfileId = table.Column<int>(type: "INTEGER", nullable: false),
                    IdentifierValue = table.Column<string>(type: "TEXT", maxLength: 253, nullable: false),
                    Note = table.Column<string>(type: "TEXT", maxLength: 500, nullable: true),
                    CreatedAt = table.Column<DateTime>(type: "TEXT", nullable: false)
                },
                constraints: table =>
                {
                    table.PrimaryKey("PK_DeviceAllowlistEntries", x => x.Id);
                    table.ForeignKey(
                        name: "FK_DeviceAllowlistEntries_DeviceAttestationProfiles_ProfileId",
                        column: x => x.ProfileId,
                        principalTable: "DeviceAttestationProfiles",
                        principalColumn: "Id",
                        onDelete: ReferentialAction.Cascade);
                });

            migrationBuilder.CreateIndex(
                name: "IX_AttestationTrustAnchors_Format",
                table: "AttestationTrustAnchors",
                column: "Format");

            migrationBuilder.CreateIndex(
                name: "IX_AttestationTrustAnchors_Sha256Fingerprint",
                table: "AttestationTrustAnchors",
                column: "Sha256Fingerprint",
                unique: true);

            migrationBuilder.CreateIndex(
                name: "IX_DeviceAllowlistEntries_ProfileId_IdentifierValue",
                table: "DeviceAllowlistEntries",
                columns: new[] { "ProfileId", "IdentifierValue" },
                unique: true);

            migrationBuilder.CreateIndex(
                name: "IX_DeviceAttestationProfiles_TemplateId",
                table: "DeviceAttestationProfiles",
                column: "TemplateId",
                unique: true);
        }

        /// <inheritdoc />
        protected override void Down(MigrationBuilder migrationBuilder)
        {
            migrationBuilder.DropTable(
                name: "AttestationTrustAnchors");

            migrationBuilder.DropTable(
                name: "DeviceAllowlistEntries");

            migrationBuilder.DropTable(
                name: "DeviceAttestationProfiles");

            migrationBuilder.DropColumn(
                name: "AttestationObject",
                table: "AcmeChallenges");

            migrationBuilder.DropColumn(
                name: "AttestationFormat",
                table: "AcmeAuthorizations");

            migrationBuilder.DropColumn(
                name: "AttestedPropertiesJson",
                table: "AcmeAuthorizations");

            migrationBuilder.DropColumn(
                name: "AttestedSpki",
                table: "AcmeAuthorizations");
        }
    }
}
