using Microsoft.EntityFrameworkCore.Migrations;

#nullable disable

namespace Certus.Core.Data.Migrations
{
    /// <inheritdoc />
    public partial class AddSyncedCertificateSupersession : Migration
    {
        /// <inheritdoc />
        protected override void Up(MigrationBuilder migrationBuilder)
        {
            migrationBuilder.AddColumn<int>(
                name: "SupersededByCertificateId",
                table: "SyncedCertificates",
                type: "INTEGER",
                nullable: true);

            migrationBuilder.CreateIndex(
                name: "IX_SyncedCertificates_SupersededByCertificateId",
                table: "SyncedCertificates",
                column: "SupersededByCertificateId");
        }

        /// <inheritdoc />
        protected override void Down(MigrationBuilder migrationBuilder)
        {
            migrationBuilder.DropIndex(
                name: "IX_SyncedCertificates_SupersededByCertificateId",
                table: "SyncedCertificates");

            migrationBuilder.DropColumn(
                name: "SupersededByCertificateId",
                table: "SyncedCertificates");
        }
    }
}
