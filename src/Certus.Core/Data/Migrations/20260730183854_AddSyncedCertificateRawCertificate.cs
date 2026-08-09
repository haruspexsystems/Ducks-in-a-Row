using Microsoft.EntityFrameworkCore.Migrations;

#nullable disable

namespace Certus.Core.Data.Migrations
{
    /// <inheritdoc />
    public partial class AddSyncedCertificateRawCertificate : Migration
    {
        /// <inheritdoc />
        protected override void Up(MigrationBuilder migrationBuilder)
        {
            migrationBuilder.AddColumn<byte[]>(
                name: "RawCertificate",
                table: "SyncedCertificates",
                type: "BLOB",
                nullable: true);
        }

        /// <inheritdoc />
        protected override void Down(MigrationBuilder migrationBuilder)
        {
            migrationBuilder.DropColumn(
                name: "RawCertificate",
                table: "SyncedCertificates");
        }
    }
}
