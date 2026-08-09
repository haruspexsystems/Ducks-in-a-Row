using Microsoft.EntityFrameworkCore.Migrations;

#nullable disable

namespace Certus.Core.Data.Migrations
{
    /// <inheritdoc />
    public partial class AddSyncedCertificateCryptoDetail : Migration
    {
        /// <inheritdoc />
        protected override void Up(MigrationBuilder migrationBuilder)
        {
            migrationBuilder.AddColumn<string>(
                name: "ExtendedKeyUsageOids",
                table: "SyncedCertificates",
                type: "TEXT",
                maxLength: 1000,
                nullable: true);

            migrationBuilder.AddColumn<string>(
                name: "KeyAlgorithm",
                table: "SyncedCertificates",
                type: "TEXT",
                maxLength: 40,
                nullable: true);

            migrationBuilder.AddColumn<int>(
                name: "KeySizeBits",
                table: "SyncedCertificates",
                type: "INTEGER",
                nullable: true);

            migrationBuilder.AddColumn<int>(
                name: "KeyUsage",
                table: "SyncedCertificates",
                type: "INTEGER",
                nullable: true);

            migrationBuilder.AddColumn<string>(
                name: "Sha256Thumbprint",
                table: "SyncedCertificates",
                type: "TEXT",
                maxLength: 64,
                nullable: true);

            migrationBuilder.AddColumn<string>(
                name: "SignatureAlgorithmOid",
                table: "SyncedCertificates",
                type: "TEXT",
                maxLength: 64,
                nullable: true);
        }

        /// <inheritdoc />
        protected override void Down(MigrationBuilder migrationBuilder)
        {
            migrationBuilder.DropColumn(
                name: "ExtendedKeyUsageOids",
                table: "SyncedCertificates");

            migrationBuilder.DropColumn(
                name: "KeyAlgorithm",
                table: "SyncedCertificates");

            migrationBuilder.DropColumn(
                name: "KeySizeBits",
                table: "SyncedCertificates");

            migrationBuilder.DropColumn(
                name: "KeyUsage",
                table: "SyncedCertificates");

            migrationBuilder.DropColumn(
                name: "Sha256Thumbprint",
                table: "SyncedCertificates");

            migrationBuilder.DropColumn(
                name: "SignatureAlgorithmOid",
                table: "SyncedCertificates");
        }
    }
}
