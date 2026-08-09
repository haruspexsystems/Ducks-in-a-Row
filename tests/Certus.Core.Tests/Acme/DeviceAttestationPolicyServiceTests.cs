using Certus.Core.Acme.Services;
using Certus.Core.Data;
using Certus.Core.Data.Entities;
using Microsoft.Data.Sqlite;
using Microsoft.EntityFrameworkCore;

namespace Certus.Core.Tests.Acme;

/// <summary>
/// Tests for the device attestation gate. The load bearing property is that
/// every unknown state answers closed: no profile, a disabled profile, an
/// unknown gate mode, an empty allowlist, and a near miss identifier all
/// refuse. Only an explicit listing or the explicit open mode admits.
/// </summary>
public class DeviceAttestationPolicyServiceTests : IDisposable
{
    private const string TestTemplate = "DeviceAuth";
    private const string TestDevice = "PROBE-SN-0001";

    private readonly SqliteConnection _connection;
    private readonly CertusDbContext _db;
    private readonly DeviceAttestationPolicyService _sut;

    public DeviceAttestationPolicyServiceTests()
    {
        _connection = new SqliteConnection("Data Source=:memory:");
        _connection.Open();

        var options = new DbContextOptionsBuilder<CertusDbContext>()
            .UseSqlite(_connection)
            .Options;
        _db = new CertusDbContext(options);
        _db.Database.EnsureCreated();

        _sut = new DeviceAttestationPolicyService(_db);
    }

    private void SeedProfile(
        string templateId = TestTemplate,
        bool enabled = true,
        string gateMode = DeviceAttestationGateModes.Allowlist,
        params string[] devices)
    {
        var profile = new DeviceAttestationProfile
        {
            TemplateId = templateId,
            Enabled = enabled,
            GateMode = gateMode
        };
        foreach (var device in devices)
            profile.AllowlistEntries.Add(new DeviceAllowlistEntry { IdentifierValue = device });

        _db.DeviceAttestationProfiles.Add(profile);
        _db.SaveChanges();
        _db.ChangeTracker.Clear();
    }

    [Fact]
    public async Task Check_NoProfile_ReturnsNoProfile()
    {
        var outcome = await _sut.CheckAsync(TestTemplate, TestDevice);

        outcome.Should().Be(DeviceAttestationPolicyOutcome.NoProfile);
    }

    [Fact]
    public async Task Check_DisabledProfile_RefusesEvenListedDevices()
    {
        SeedProfile(enabled: false, devices: TestDevice);

        var outcome = await _sut.CheckAsync(TestTemplate, TestDevice);

        outcome.Should().Be(DeviceAttestationPolicyOutcome.Disabled);
    }

    [Fact]
    public async Task Check_OpenMode_AdmitsUnlistedDevice()
    {
        SeedProfile(gateMode: DeviceAttestationGateModes.Open);

        var outcome = await _sut.CheckAsync(TestTemplate, "NEVER-LISTED");

        outcome.Should().Be(DeviceAttestationPolicyOutcome.AllowedOpen);
    }

    [Fact]
    public async Task Check_AllowlistMode_ListedDevice_IsAdmitted()
    {
        SeedProfile(devices: new[] { "OTHER-SN", TestDevice });

        var outcome = await _sut.CheckAsync(TestTemplate, TestDevice);

        outcome.Should().Be(DeviceAttestationPolicyOutcome.AllowedListed);
    }

    [Fact]
    public async Task Check_AllowlistMode_UnlistedDevice_Refuses()
    {
        SeedProfile(devices: "OTHER-SN");

        var outcome = await _sut.CheckAsync(TestTemplate, TestDevice);

        outcome.Should().Be(DeviceAttestationPolicyOutcome.NotOnAllowlist);
    }

    [Fact]
    public async Task Check_AllowlistMode_EmptyAllowlist_RefusesEverything()
    {
        SeedProfile();

        var outcome = await _sut.CheckAsync(TestTemplate, TestDevice);

        outcome.Should().Be(DeviceAttestationPolicyOutcome.NotOnAllowlist);
    }

    [Fact]
    public async Task Check_UnknownGateMode_BehavesAsAllowlist()
    {
        // A future or hand edited mode value must never widen admission.
        SeedProfile(gateMode: "permissive");

        var outcome = await _sut.CheckAsync(TestTemplate, TestDevice);

        outcome.Should().Be(DeviceAttestationPolicyOutcome.NotOnAllowlist);
    }

    [Fact]
    public async Task Check_IdentifierCompare_IsOctetExact()
    {
        SeedProfile(devices: TestDevice);

        var outcome = await _sut.CheckAsync(TestTemplate, TestDevice.ToLowerInvariant());

        outcome.Should().Be(
            DeviceAttestationPolicyOutcome.NotOnAllowlist,
            "the draft compares identifiers octet for octet, so a case lookalike must not be admitted");
    }

    [Fact]
    public async Task Check_ProfileIsTemplateScoped()
    {
        SeedProfile(templateId: "WebServer", devices: TestDevice);

        var outcome = await _sut.CheckAsync(TestTemplate, TestDevice);

        outcome.Should().Be(DeviceAttestationPolicyOutcome.NoProfile);
    }

    [Fact]
    public async Task GetProfile_ReturnsProfileForTemplate()
    {
        SeedProfile(gateMode: DeviceAttestationGateModes.Open);

        var profile = await _sut.GetProfileAsync(TestTemplate);

        profile.Should().NotBeNull();
        profile!.TemplateId.Should().Be(TestTemplate);
        profile.GateMode.Should().Be(DeviceAttestationGateModes.Open);
        profile.CsrIdentifierBinding.Should().Be(CsrIdentifierBindingModes.CnOrSan);

        (await _sut.GetProfileAsync("Unconfigured")).Should().BeNull();
    }

    public void Dispose()
    {
        _db.Dispose();
        _connection.Close();
        _connection.Dispose();
    }
}
