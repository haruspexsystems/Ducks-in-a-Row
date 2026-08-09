using Microsoft.EntityFrameworkCore.Migrations;

#nullable disable

namespace Certus.Core.Data.Migrations
{
    /// <inheritdoc />
    public partial class AddAcmeAccountListIndexes : Migration
    {
        /// <inheritdoc />
        protected override void Up(MigrationBuilder migrationBuilder)
        {
            migrationBuilder.DropIndex(
                name: "IX_AcmeOrders_AccountId",
                table: "AcmeOrders");

            migrationBuilder.CreateIndex(
                name: "IX_AcmeOrders_AccountId_CreatedAt",
                table: "AcmeOrders",
                columns: new[] { "AccountId", "CreatedAt" });

            migrationBuilder.CreateIndex(
                name: "IX_AcmeAccounts_CreatedAt",
                table: "AcmeAccounts",
                column: "CreatedAt");

            migrationBuilder.CreateIndex(
                name: "IX_AcmeAccounts_Status",
                table: "AcmeAccounts",
                column: "Status");
        }

        /// <inheritdoc />
        protected override void Down(MigrationBuilder migrationBuilder)
        {
            migrationBuilder.DropIndex(
                name: "IX_AcmeOrders_AccountId_CreatedAt",
                table: "AcmeOrders");

            migrationBuilder.DropIndex(
                name: "IX_AcmeAccounts_CreatedAt",
                table: "AcmeAccounts");

            migrationBuilder.DropIndex(
                name: "IX_AcmeAccounts_Status",
                table: "AcmeAccounts");

            migrationBuilder.CreateIndex(
                name: "IX_AcmeOrders_AccountId",
                table: "AcmeOrders",
                column: "AccountId");
        }
    }
}
