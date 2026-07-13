using System.Net;
using System.Text.Json;

namespace Certus.Web.Tests;

/// <summary>
/// Fleet health empty state: on a fresh install with nothing scoreable the
/// score must serialize as JSON null (the frontend renders "No certificates
/// yet"), not default to a misleading 100.
///
/// Uses a dedicated factory instead of the shared "ACME Integration"
/// collection, whose database is seeded with issued certificates by sibling
/// tests. The mock ADCS client's inventory starts empty, so even a background
/// sync tick leaves the database without scoreable rows here.
/// </summary>
[Trait("Category", "Integration")]
public class FleetHealthEmptyStateIntegrationTests : IClassFixture<CertusWebApplicationFactory>
{
    private readonly HttpClient _client;

    public FleetHealthEmptyStateIntegrationTests(CertusWebApplicationFactory factory)
    {
        _client = factory.CreateClient();
    }

    [Fact]
    public async Task Health_EmptyInventory_ReturnsNullScoreAndZeroSegments()
    {
        var response = await _client.GetAsync("/api/dashboard/health");
        response.StatusCode.Should().Be(HttpStatusCode.OK);

        var body = JsonSerializer.Deserialize<JsonElement>(
            await response.Content.ReadAsStringAsync());

        body.GetProperty("score").ValueKind.Should().Be(JsonValueKind.Null);
        body.GetProperty("segments").EnumerateArray()
            .Sum(s => s.GetProperty("count").GetInt32())
            .Should().Be(0);
    }
}
