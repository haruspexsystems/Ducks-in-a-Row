using System;
using Microsoft.EntityFrameworkCore.Migrations;

#nullable disable

namespace Certus.Core.Data.Migrations
{
    /// <inheritdoc />
    public partial class AddDomainPolicyRejections : Migration
    {
        /// <inheritdoc />
        protected override void Up(MigrationBuilder migrationBuilder)
        {
            migrationBuilder.CreateTable(
                name: "DomainPolicyRejections",
                columns: table => new
                {
                    Id = table.Column<int>(type: "INTEGER", nullable: false)
                        .Annotation("Sqlite:Autoincrement", true),
                    OccurredAt = table.Column<DateTime>(type: "TEXT", nullable: false),
                    AccountId = table.Column<string>(type: "TEXT", maxLength: 64, nullable: false),
                    TemplateId = table.Column<string>(type: "TEXT", maxLength: 200, nullable: false),
                    RequestedIdentifiers = table.Column<string>(type: "TEXT", maxLength: 2000, nullable: false),
                    RejectedIdentifiers = table.Column<string>(type: "TEXT", maxLength: 2000, nullable: false),
                    ClientIp = table.Column<string>(type: "TEXT", maxLength: 64, nullable: true),
                    Stage = table.Column<string>(type: "TEXT", maxLength: 20, nullable: false)
                },
                constraints: table =>
                {
                    table.PrimaryKey("PK_DomainPolicyRejections", x => x.Id);
                });

            migrationBuilder.CreateIndex(
                name: "IX_DomainPolicyRejections_OccurredAt",
                table: "DomainPolicyRejections",
                column: "OccurredAt");
        }

        /// <inheritdoc />
        protected override void Down(MigrationBuilder migrationBuilder)
        {
            migrationBuilder.DropTable(
                name: "DomainPolicyRejections");
        }
    }
}
