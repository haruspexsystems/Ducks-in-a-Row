using Microsoft.EntityFrameworkCore.Migrations;

#nullable disable

namespace Certus.Core.Data.Migrations
{
    /// <inheritdoc />
    public partial class AddSyncedCertificateDateSortIndexes : Migration
    {
        /// <inheritdoc />
        protected override void Up(MigrationBuilder migrationBuilder)
        {
            migrationBuilder.CreateIndex(
                name: "IX_SyncedCertificates_NotBefore",
                table: "SyncedCertificates",
                column: "NotBefore");

            migrationBuilder.CreateIndex(
                name: "IX_SyncedCertificates_RequestDate",
                table: "SyncedCertificates",
                column: "RequestDate");
        }

        /// <inheritdoc />
        protected override void Down(MigrationBuilder migrationBuilder)
        {
            migrationBuilder.DropIndex(
                name: "IX_SyncedCertificates_NotBefore",
                table: "SyncedCertificates");

            migrationBuilder.DropIndex(
                name: "IX_SyncedCertificates_RequestDate",
                table: "SyncedCertificates");
        }
    }
}
