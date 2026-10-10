using Microsoft.EntityFrameworkCore.Migrations;

#nullable disable

namespace Certus.Core.Data.Migrations
{
    /// <inheritdoc />
    public partial class AddAcmeOrderReplaces : Migration
    {
        /// <inheritdoc />
        protected override void Up(MigrationBuilder migrationBuilder)
        {
            migrationBuilder.AddColumn<string>(
                name: "ReplacesCertificateId",
                table: "AcmeOrders",
                type: "TEXT",
                maxLength: 128,
                nullable: true);

            migrationBuilder.CreateIndex(
                name: "IX_AcmeOrders_ReplacesCertificateId",
                table: "AcmeOrders",
                column: "ReplacesCertificateId",
                filter: "\"ReplacesCertificateId\" IS NOT NULL");
        }

        /// <inheritdoc />
        protected override void Down(MigrationBuilder migrationBuilder)
        {
            migrationBuilder.DropIndex(
                name: "IX_AcmeOrders_ReplacesCertificateId",
                table: "AcmeOrders");

            migrationBuilder.DropColumn(
                name: "ReplacesCertificateId",
                table: "AcmeOrders");
        }
    }
}
