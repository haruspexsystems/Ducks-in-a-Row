using System;
using Microsoft.EntityFrameworkCore.Migrations;

#nullable disable

namespace Certus.Core.Data.Migrations
{
    /// <inheritdoc />
    public partial class InitialCreate : Migration
    {
        /// <inheritdoc />
        protected override void Up(MigrationBuilder migrationBuilder)
        {
            migrationBuilder.CreateTable(
                name: "AcmeAccounts",
                columns: table => new
                {
                    Id = table.Column<int>(type: "INTEGER", nullable: false)
                        .Annotation("Sqlite:Autoincrement", true),
                    AccountId = table.Column<string>(type: "TEXT", maxLength: 64, nullable: false),
                    JwkJson = table.Column<string>(type: "TEXT", nullable: false),
                    JwkThumbprint = table.Column<string>(type: "TEXT", maxLength: 64, nullable: false),
                    ContactJson = table.Column<string>(type: "TEXT", nullable: true),
                    Status = table.Column<string>(type: "TEXT", maxLength: 20, nullable: false, defaultValue: "valid"),
                    TermsOfServiceAgreed = table.Column<bool>(type: "INTEGER", nullable: false),
                    CreatedAt = table.Column<DateTime>(type: "TEXT", nullable: false),
                    UpdatedAt = table.Column<DateTime>(type: "TEXT", nullable: true)
                },
                constraints: table =>
                {
                    table.PrimaryKey("PK_AcmeAccounts", x => x.Id);
                });

            migrationBuilder.CreateTable(
                name: "SyncedCertificates",
                columns: table => new
                {
                    Id = table.Column<int>(type: "INTEGER", nullable: false)
                        .Annotation("Sqlite:Autoincrement", true),
                    RequestId = table.Column<int>(type: "INTEGER", nullable: false),
                    SerialNumber = table.Column<string>(type: "TEXT", maxLength: 64, nullable: false),
                    Subject = table.Column<string>(type: "TEXT", maxLength: 500, nullable: false),
                    SubjectAlternativeNames = table.Column<string>(type: "TEXT", maxLength: 2000, nullable: true),
                    TemplateName = table.Column<string>(type: "TEXT", maxLength: 200, nullable: false),
                    NotBefore = table.Column<DateTime>(type: "TEXT", nullable: false),
                    NotAfter = table.Column<DateTime>(type: "TEXT", nullable: false),
                    Status = table.Column<string>(type: "TEXT", maxLength: 20, nullable: false),
                    Requestor = table.Column<string>(type: "TEXT", maxLength: 256, nullable: true),
                    RequestDate = table.Column<DateTime>(type: "TEXT", nullable: false),
                    FirstSyncedAt = table.Column<DateTime>(type: "TEXT", nullable: false),
                    LastSyncedAt = table.Column<DateTime>(type: "TEXT", nullable: false)
                },
                constraints: table =>
                {
                    table.PrimaryKey("PK_SyncedCertificates", x => x.Id);
                });

            migrationBuilder.CreateTable(
                name: "AcmeOrders",
                columns: table => new
                {
                    Id = table.Column<int>(type: "INTEGER", nullable: false)
                        .Annotation("Sqlite:Autoincrement", true),
                    OrderId = table.Column<string>(type: "TEXT", maxLength: 64, nullable: false),
                    AccountId = table.Column<int>(type: "INTEGER", nullable: false),
                    Status = table.Column<string>(type: "TEXT", maxLength: 20, nullable: false, defaultValue: "pending"),
                    TemplateId = table.Column<string>(type: "TEXT", maxLength: 200, nullable: false),
                    IdentifiersJson = table.Column<string>(type: "TEXT", nullable: false),
                    NotBefore = table.Column<DateTime>(type: "TEXT", nullable: true),
                    NotAfter = table.Column<DateTime>(type: "TEXT", nullable: true),
                    CsrDer = table.Column<string>(type: "TEXT", nullable: true),
                    AdcsRequestId = table.Column<int>(type: "INTEGER", nullable: true),
                    CertificateId = table.Column<string>(type: "TEXT", nullable: true),
                    ErrorJson = table.Column<string>(type: "TEXT", nullable: true),
                    CreatedAt = table.Column<DateTime>(type: "TEXT", nullable: false),
                    ExpiresAt = table.Column<DateTime>(type: "TEXT", nullable: false)
                },
                constraints: table =>
                {
                    table.PrimaryKey("PK_AcmeOrders", x => x.Id);
                    table.ForeignKey(
                        name: "FK_AcmeOrders_AcmeAccounts_AccountId",
                        column: x => x.AccountId,
                        principalTable: "AcmeAccounts",
                        principalColumn: "Id",
                        onDelete: ReferentialAction.Cascade);
                });

            migrationBuilder.CreateTable(
                name: "AlertsSent",
                columns: table => new
                {
                    Id = table.Column<int>(type: "INTEGER", nullable: false)
                        .Annotation("Sqlite:Autoincrement", true),
                    CertificateId = table.Column<int>(type: "INTEGER", nullable: false),
                    ThresholdDays = table.Column<int>(type: "INTEGER", nullable: false),
                    SentAt = table.Column<DateTime>(type: "TEXT", nullable: false),
                    Channels = table.Column<string>(type: "TEXT", maxLength: 50, nullable: false),
                    Success = table.Column<bool>(type: "INTEGER", nullable: false),
                    ErrorMessage = table.Column<string>(type: "TEXT", maxLength: 1000, nullable: true)
                },
                constraints: table =>
                {
                    table.PrimaryKey("PK_AlertsSent", x => x.Id);
                    table.ForeignKey(
                        name: "FK_AlertsSent_SyncedCertificates_CertificateId",
                        column: x => x.CertificateId,
                        principalTable: "SyncedCertificates",
                        principalColumn: "Id",
                        onDelete: ReferentialAction.Cascade);
                });

            migrationBuilder.CreateTable(
                name: "AcmeAuthorizations",
                columns: table => new
                {
                    Id = table.Column<int>(type: "INTEGER", nullable: false)
                        .Annotation("Sqlite:Autoincrement", true),
                    AuthorizationId = table.Column<string>(type: "TEXT", maxLength: 64, nullable: false),
                    OrderId = table.Column<int>(type: "INTEGER", nullable: false),
                    IdentifierType = table.Column<string>(type: "TEXT", maxLength: 10, nullable: false),
                    IdentifierValue = table.Column<string>(type: "TEXT", maxLength: 253, nullable: false),
                    Status = table.Column<string>(type: "TEXT", maxLength: 20, nullable: false, defaultValue: "pending"),
                    Wildcard = table.Column<bool>(type: "INTEGER", nullable: false),
                    CreatedAt = table.Column<DateTime>(type: "TEXT", nullable: false),
                    ExpiresAt = table.Column<DateTime>(type: "TEXT", nullable: false)
                },
                constraints: table =>
                {
                    table.PrimaryKey("PK_AcmeAuthorizations", x => x.Id);
                    table.ForeignKey(
                        name: "FK_AcmeAuthorizations_AcmeOrders_OrderId",
                        column: x => x.OrderId,
                        principalTable: "AcmeOrders",
                        principalColumn: "Id",
                        onDelete: ReferentialAction.Cascade);
                });

            migrationBuilder.CreateTable(
                name: "AcmeCertificates",
                columns: table => new
                {
                    Id = table.Column<int>(type: "INTEGER", nullable: false)
                        .Annotation("Sqlite:Autoincrement", true),
                    CertificateId = table.Column<string>(type: "TEXT", maxLength: 64, nullable: false),
                    OrderId = table.Column<int>(type: "INTEGER", nullable: false),
                    CertificatePem = table.Column<string>(type: "TEXT", nullable: false),
                    AdcsRequestId = table.Column<int>(type: "INTEGER", nullable: false),
                    SerialNumber = table.Column<string>(type: "TEXT", maxLength: 64, nullable: false),
                    IssuedAt = table.Column<DateTime>(type: "TEXT", nullable: false),
                    RevokedAt = table.Column<DateTime>(type: "TEXT", nullable: true),
                    RevokedReason = table.Column<int>(type: "INTEGER", nullable: true)
                },
                constraints: table =>
                {
                    table.PrimaryKey("PK_AcmeCertificates", x => x.Id);
                    table.ForeignKey(
                        name: "FK_AcmeCertificates_AcmeOrders_OrderId",
                        column: x => x.OrderId,
                        principalTable: "AcmeOrders",
                        principalColumn: "Id",
                        onDelete: ReferentialAction.Cascade);
                });

            migrationBuilder.CreateTable(
                name: "AcmeChallenges",
                columns: table => new
                {
                    Id = table.Column<int>(type: "INTEGER", nullable: false)
                        .Annotation("Sqlite:Autoincrement", true),
                    ChallengeId = table.Column<string>(type: "TEXT", maxLength: 64, nullable: false),
                    AuthorizationId = table.Column<int>(type: "INTEGER", nullable: false),
                    Type = table.Column<string>(type: "TEXT", maxLength: 20, nullable: false),
                    Token = table.Column<string>(type: "TEXT", maxLength: 256, nullable: false),
                    Status = table.Column<string>(type: "TEXT", maxLength: 20, nullable: false, defaultValue: "pending"),
                    ValidatedAt = table.Column<DateTime>(type: "TEXT", nullable: true),
                    ValidationAttempts = table.Column<int>(type: "INTEGER", nullable: false),
                    LastAttemptAt = table.Column<DateTime>(type: "TEXT", nullable: true),
                    ErrorJson = table.Column<string>(type: "TEXT", nullable: true)
                },
                constraints: table =>
                {
                    table.PrimaryKey("PK_AcmeChallenges", x => x.Id);
                    table.ForeignKey(
                        name: "FK_AcmeChallenges_AcmeAuthorizations_AuthorizationId",
                        column: x => x.AuthorizationId,
                        principalTable: "AcmeAuthorizations",
                        principalColumn: "Id",
                        onDelete: ReferentialAction.Cascade);
                });

            migrationBuilder.CreateIndex(
                name: "IX_AcmeAccounts_AccountId",
                table: "AcmeAccounts",
                column: "AccountId",
                unique: true);

            migrationBuilder.CreateIndex(
                name: "IX_AcmeAccounts_JwkThumbprint",
                table: "AcmeAccounts",
                column: "JwkThumbprint",
                unique: true);

            migrationBuilder.CreateIndex(
                name: "IX_AcmeAuthorizations_AuthorizationId",
                table: "AcmeAuthorizations",
                column: "AuthorizationId",
                unique: true);

            migrationBuilder.CreateIndex(
                name: "IX_AcmeAuthorizations_OrderId",
                table: "AcmeAuthorizations",
                column: "OrderId");

            migrationBuilder.CreateIndex(
                name: "IX_AcmeCertificates_CertificateId",
                table: "AcmeCertificates",
                column: "CertificateId",
                unique: true);

            migrationBuilder.CreateIndex(
                name: "IX_AcmeCertificates_OrderId",
                table: "AcmeCertificates",
                column: "OrderId");

            migrationBuilder.CreateIndex(
                name: "IX_AcmeCertificates_SerialNumber",
                table: "AcmeCertificates",
                column: "SerialNumber");

            migrationBuilder.CreateIndex(
                name: "IX_AcmeChallenges_AuthorizationId",
                table: "AcmeChallenges",
                column: "AuthorizationId");

            migrationBuilder.CreateIndex(
                name: "IX_AcmeChallenges_ChallengeId",
                table: "AcmeChallenges",
                column: "ChallengeId",
                unique: true);

            migrationBuilder.CreateIndex(
                name: "IX_AcmeChallenges_Status",
                table: "AcmeChallenges",
                column: "Status");

            migrationBuilder.CreateIndex(
                name: "IX_AcmeOrders_AccountId",
                table: "AcmeOrders",
                column: "AccountId");

            migrationBuilder.CreateIndex(
                name: "IX_AcmeOrders_OrderId",
                table: "AcmeOrders",
                column: "OrderId",
                unique: true);

            migrationBuilder.CreateIndex(
                name: "IX_AlertsSent_CertificateId_ThresholdDays",
                table: "AlertsSent",
                columns: new[] { "CertificateId", "ThresholdDays" },
                unique: true);

            migrationBuilder.CreateIndex(
                name: "IX_SyncedCertificates_NotAfter",
                table: "SyncedCertificates",
                column: "NotAfter");

            migrationBuilder.CreateIndex(
                name: "IX_SyncedCertificates_RequestId",
                table: "SyncedCertificates",
                column: "RequestId",
                unique: true);

            migrationBuilder.CreateIndex(
                name: "IX_SyncedCertificates_SerialNumber",
                table: "SyncedCertificates",
                column: "SerialNumber");

            migrationBuilder.CreateIndex(
                name: "IX_SyncedCertificates_Status",
                table: "SyncedCertificates",
                column: "Status");

            migrationBuilder.CreateIndex(
                name: "IX_SyncedCertificates_Subject",
                table: "SyncedCertificates",
                column: "Subject");

            migrationBuilder.CreateIndex(
                name: "IX_SyncedCertificates_TemplateName",
                table: "SyncedCertificates",
                column: "TemplateName");
        }

        /// <inheritdoc />
        protected override void Down(MigrationBuilder migrationBuilder)
        {
            migrationBuilder.DropTable(
                name: "AcmeCertificates");

            migrationBuilder.DropTable(
                name: "AcmeChallenges");

            migrationBuilder.DropTable(
                name: "AlertsSent");

            migrationBuilder.DropTable(
                name: "AcmeAuthorizations");

            migrationBuilder.DropTable(
                name: "SyncedCertificates");

            migrationBuilder.DropTable(
                name: "AcmeOrders");

            migrationBuilder.DropTable(
                name: "AcmeAccounts");
        }
    }
}
