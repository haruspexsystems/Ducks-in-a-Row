using System.Net;
using System.Net.Http.Headers;
using System.Security.Cryptography;
using System.Security.Cryptography.X509Certificates;
using Certus.Core.Acme.Models;
using Certus.Core.Acme.Services;
using Certus.Core.Modules;
using Certus.Core.Tests.Acme.Attestation;
using Certus.Tests.Shared;
using Certus.Web.Controllers.Settings;

namespace Certus.Service.Tests.Modules;

/// <summary>
/// The named proof of the licence invariant (licence design sections 2.5 and 18.1, issue #413): no
/// state of the paid module stops, delays or changes issuance, renewal or revocation. Each state
/// boots the real service host with the mock CA and drives the whole flow through it:
///
/// <list type="number">
/// <item>a device-attest-01 order in open mode reaches valid;</item>
/// <item>a renewal order whose <c>replaces</c> names the first certificate reaches valid;</item>
/// <item>revoke-cert of the first certificate succeeds;</item>
/// <item>after three module host ticks the host still answers the directory;</item>
/// <item><c>GET api/settings/licence</c> never answers a server error, at any point.</item>
/// </list>
///
/// <para>Every state is first proved to be the state it claims, from the API's own answer, so a
/// setup mistake that left every host with no module could not make the proof vacuous.</para>
/// </summary>
public class LicenceInvariantHostTests
{
    private const string Serial = "SN-INVARIANT-0001";
    private const string Udid = "00008030-000A1B2C3D4E5F62";

    private static readonly TimeSpan StateTimeout = TimeSpan.FromSeconds(30);
    private static readonly TimeSpan ValidationTimeout = TimeSpan.FromSeconds(30);

    public static TheoryData<ModuleScenario> EveryModuleState()
    {
        var data = new TheoryData<ModuleScenario>();
        foreach (var scenario in Enum.GetValues<ModuleScenario>())
            data.Add(scenario);
        return data;
    }

    [Theory]
    [MemberData(nameof(EveryModuleState))]
    public async Task IssuanceRenewalAndRevocation_AreUnaffected_ByAnyModuleState(ModuleScenario scenario)
    {
        using var factory = new ModuleScenarioHostFactory(scenario);
        using var http = factory.CreateClient();

        await ProveTheStateAsync(factory, http);

        using var root = SyntheticAttestationBuilder.CreateRoot();
        await factory.SeedOpenDeviceProfileAsync(root);
        using var acme = new AcmeTestClient(http, ServiceHostFactory.Template);
        await acme.CreateAccountAsync();

        // 1. A device order reaches valid.
        using var first = await IssueDeviceCertificateAsync(acme, root, replaces: null);
        await ModuleScenarioHostFactory.GetLicenceAsync(http);

        // 2. A renewal naming the first certificate reaches valid.
        var replaces = AriCertificateId.FromCertificate(first)!;
        using var renewed = await IssueDeviceCertificateAsync(acme, root, replaces);
        renewed.SerialNumber.Should().NotBe(first.SerialNumber);

        // The licence API is asked about a candidate mid flow too, while the issuance path is busy,
        // and in no state may it answer with a server error. In the throwing state the module was
        // set aside at its first evaluation, so this inspect is answered without calling it; an
        // Inspect that throws from a module still loaded is ModuleHostTests' to prove.
        var inspect = await InspectAsync(http);
        ((int)inspect.StatusCode).Should().BeLessThan(500, await inspect.Content.ReadAsStringAsync());

        // 3. revoke-cert of the first certificate succeeds.
        var revoked = await acme.RevokeAsync(first.RawData);
        revoked.StatusCode.Should().Be(HttpStatusCode.OK, await revoked.Content.ReadAsStringAsync());

        // 4. After three module host ticks the host still answers the directory.
        await factory.AdvanceModuleTicksAsync(3);
        var directory = await http.GetAsync($"/acme/{ServiceHostFactory.Template}/directory");
        directory.StatusCode.Should().Be(HttpStatusCode.OK);

        // 5. And the licence status still answers, in the same state.
        var after = await ModuleScenarioHostFactory.GetLicenceAsync(http);
        after.Module.State.Should().Be(ExpectedState(scenario));
    }

    [Fact]
    public async Task HostServesAcme_BeforeTheModuleFinishesLoading()
    {
        var module = new BlockingStartModule();
        using var factory = new ModuleScenarioHostFactory(ModuleScenario.Valid, module);

        // Booting runs every hosted service's StartAsync. A module host that waited for the module
        // there would hold the boot for as long as Start is held, so the boot itself is bounded: a
        // regression reports here rather than hanging the run.
        using var http = await PoolAwareWait.Bounded(
            Task.Run(() => factory.CreateClient()),
            "the service host to boot while the module's Start is held");

        module.WaitUntilEntered(TimeSpan.FromSeconds(30)).Should().BeTrue(
            "the module host calls Start once the application has started");

        // Start is still held. ACME answers regardless, and so does the licence status.
        (await http.GetAsync($"/acme/{ServiceHostFactory.Template}/directory")).StatusCode.Should().Be(HttpStatusCode.OK);
        (await http.GetAsync($"/acme/{ServiceHostFactory.Template}/new-nonce")).IsSuccessStatusCode.Should().BeTrue();
        var during = await ModuleScenarioHostFactory.GetLicenceAsync(http);
        during.Module.State.Should().NotBe("Loaded", "Start has not returned");

        module.Release();
        var loaded = await factory.WaitForModuleStateAsync(http, "Loaded", StateTimeout);
        loaded.Module.State.Should().Be("Loaded");
    }

    /// <summary>The module state each scenario must actually reach, read back from the API.</summary>
    private static string ExpectedState(ModuleScenario scenario) => scenario switch
    {
        ModuleScenario.NoModule => "NotPresent",
        ModuleScenario.Valid or ModuleScenario.Expired or ModuleScenario.Lapsed or ModuleScenario.BindingMismatch => "Loaded",
        ModuleScenario.ThrowsEverywhere => "Failed",
        ModuleScenario.Incompatible => "Incompatible", // issue #493: its own state, not Failed
        ModuleScenario.RefusedByGate => "Refused",
        ModuleScenario.Hangs => "Unresponsive",
        ModuleScenario.Quarantined => "Quarantined",
        _ => throw new ArgumentOutOfRangeException(nameof(scenario)),
    };

    private static async Task ProveTheStateAsync(ModuleScenarioHostFactory factory, HttpClient http)
    {
        var expected = ExpectedState(factory.Scenario);
        var status = await factory.WaitForModuleStateAsync(http, expected, StateTimeout);
        status.Module.State.Should().Be(expected, status.Module.Reason);
        status.Stored.Active.Should().BeTrue();

        switch (factory.Scenario)
        {
            case ModuleScenario.NoModule:
                status.Licence.Status.Should().Be("StoredNotVerified");
                break;
            case ModuleScenario.Valid:
                (await LicenceStatusOnceEvaluatedAsync(factory, http)).Should().Be("Valid");
                break;
            case ModuleScenario.Expired:
                (await LicenceStatusOnceEvaluatedAsync(factory, http)).Should().Be("Grace");
                break;
            case ModuleScenario.Lapsed:
                (await LicenceStatusOnceEvaluatedAsync(factory, http)).Should().Be("Lapsed");
                break;
            case ModuleScenario.BindingMismatch:
                (await LicenceStatusOnceEvaluatedAsync(factory, http)).Should().Be("BindingMismatch");
                break;
            case ModuleScenario.ThrowsEverywhere:
                status.Module.Reason.Should().Contain("evaluating");
                break;
            case ModuleScenario.Incompatible:
                status.Module.Reason.Should().Contain("contract major 2");
                status.Module.Id.Should().Be("paid");
                status.Module.Version.Should().Be("1.0.0");
                status.Module.Contract.Should().Be(new ModuleContractView("2.0", "1.0"));
                status.Licence.Status.Should().Be("StoredNotVerified");
                break;
            case ModuleScenario.RefusedByGate:
                status.Module.Reason.Should().Contain("not trusted");
                status.Module.Contract.Should().BeNull();
                status.Licence.Status.Should().Be("StoredNotVerified");
                break;
            case ModuleScenario.Hangs:
                status.Module.Reason.Should().Contain("did not start");
                break;
            case ModuleScenario.Quarantined:
                status.Licence.Status.Should().Be("StoredNotVerified");
                break;
        }
    }

    /// <summary>A loaded module's verdict, once its first evaluation has been published.</summary>
    private static async Task<string> LicenceStatusOnceEvaluatedAsync(ModuleScenarioHostFactory factory, HttpClient http)
    {
        var deadline = DateTime.UtcNow + StateTimeout;
        while (true)
        {
            var status = await ModuleScenarioHostFactory.GetLicenceAsync(http);
            if (status.Licence.Status != "StoredNotVerified" || DateTime.UtcNow > deadline)
                return status.Licence.Status;
            await Task.Delay(100);
        }
    }

    private static Task<HttpResponseMessage> InspectAsync(HttpClient http)
    {
        var content = new ByteArrayContent(ModuleScenarioHostFactory.LicenceBytes);
        content.Headers.ContentType = new MediaTypeHeaderValue("application/jose+json");
        return http.PostAsync("/api/settings/licence/inspect", content);
    }

    /// <summary>
    /// One device-attest-01 order, from new-order to a downloaded certificate, through the open mode
    /// profile the factory seeds. Answers the issued leaf.
    /// </summary>
    private static async Task<X509Certificate2> IssueDeviceCertificateAsync(AcmeTestClient acme, X509Certificate2 root, string? replaces)
    {
        var (orderPath, order) = await acme.NewDeviceOrderAsync(Serial, replaces);
        if (replaces is not null)
            order.Replaces.Should().Be(replaces, "RFC 9773 section 5: an accepted replaces is reflected");

        var authzPath = new Uri(order.Authorizations.Single()).AbsolutePath;
        var challenge = (await acme.GetAuthorizationAsync(authzPath)).Challenges.Single();

        using var deviceKey = ECDsa.Create(ECCurve.NamedCurves.nistP256);
        using var leaf = SyntheticAttestationBuilder.CreateLeaf(
            root, Serial, Udid, SyntheticAttestationBuilder.NonceFor(challenge.Token), key: deviceKey);
        var attObj = SyntheticAttestationBuilder.ToChallengePayload(
            SyntheticAttestationBuilder.BuildAttestationObject("apple", [leaf]));

        var posted = await acme.PostAsync(new Uri(challenge.Url).AbsolutePath, new { attObj });
        posted.StatusCode.Should().Be(HttpStatusCode.OK, await posted.Content.ReadAsStringAsync());

        var authz = await AcmeTestClient.PollAsync(
            () => acme.GetAuthorizationAsync(authzPath), a => a.Status != "pending", ValidationTimeout);
        authz.Status.Should().Be("valid", authz.Challenges[0].Error?.Detail);

        var ready = await AcmeTestClient.PollAsync(
            () => acme.GetOrderAsync(orderPath), o => o.Status == "ready", ValidationTimeout);
        ready.Status.Should().Be("ready");

        var finalized = await acme.FinalizeAsync(
            new Uri(order.Finalize).AbsolutePath, DeviceCsrBuilder.Build(deviceKey, $"CN={Serial}"));
        finalized.StatusCode.Should().Be(HttpStatusCode.OK, await finalized.Content.ReadAsStringAsync());

        var issued = await acme.GetOrderAsync(orderPath);
        issued.Status.Should().Be("valid");
        issued.Certificate.Should().NotBeNullOrEmpty();

        return await acme.DownloadCertificateAsync(new Uri(issued.Certificate!).AbsolutePath);
    }
}
