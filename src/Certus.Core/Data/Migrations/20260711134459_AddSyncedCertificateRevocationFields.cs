using System;
using Microsoft.EntityFrameworkCore.Migrations;

#nullable disable

namespace Certus.Core.Data.Migrations
{
    /// <inheritdoc />
    public partial class AddSyncedCertificateRevocationFields : Migration
    {
        /// <inheritdoc />
        protected override void Up(MigrationBuilder migrationBuilder)
        {
            migrationBuilder.AddColumn<DateTime>(
                name: "RevokedAt",
                table: "SyncedCertificates",
                type: "TEXT",
                nullable: true);

            migrationBuilder.AddColumn<int>(
                name: "RevokedReason",
                table: "SyncedCertificates",
                type: "INTEGER",
                nullable: true);

            migrationBuilder.CreateIndex(
                name: "IX_AcmeCertificates_AdcsRequestId",
                table: "AcmeCertificates",
                column: "AdcsRequestId");
        }

        /// <inheritdoc />
        protected override void Down(MigrationBuilder migrationBuilder)
        {
            migrationBuilder.DropIndex(
                name: "IX_AcmeCertificates_AdcsRequestId",
                table: "AcmeCertificates");

            migrationBuilder.DropColumn(
                name: "RevokedAt",
                table: "SyncedCertificates");

            migrationBuilder.DropColumn(
                name: "RevokedReason",
                table: "SyncedCertificates");
        }
    }
}
