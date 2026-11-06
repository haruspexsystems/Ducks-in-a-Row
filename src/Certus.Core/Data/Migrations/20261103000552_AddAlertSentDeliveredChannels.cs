using Microsoft.EntityFrameworkCore.Migrations;

#nullable disable

namespace Certus.Core.Data.Migrations
{
    /// <inheritdoc />
    public partial class AddAlertSentDeliveredChannels : Migration
    {
        /// <inheritdoc />
        protected override void Up(MigrationBuilder migrationBuilder)
        {
            migrationBuilder.AddColumn<string>(
                name: "DeliveredChannels",
                table: "AlertsSent",
                type: "TEXT",
                maxLength: 50,
                nullable: true);

            // Before this column a successful row meant every attempted channel
            // delivered, so its delivered channels are known. A failed row
            // recorded only that at least one channel failed, so it stays null:
            // "unknown", never a claim that nobody was told (issue #206).
            migrationBuilder.Sql(
                "UPDATE \"AlertsSent\" SET \"DeliveredChannels\" = \"Channels\" WHERE \"Success\" = 1;");
        }

        /// <inheritdoc />
        protected override void Down(MigrationBuilder migrationBuilder)
        {
            migrationBuilder.DropColumn(
                name: "DeliveredChannels",
                table: "AlertsSent");
        }
    }
}
