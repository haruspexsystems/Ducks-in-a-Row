using System.Collections.Concurrent;
using System.Net;
using System.Net.Security;
using System.Net.Sockets;
using System.Security.Authentication;
using System.Security.Cryptography;
using System.Security.Cryptography.X509Certificates;
using Certus.Web.Security;
using Microsoft.AspNetCore.Builder;
using Microsoft.AspNetCore.Hosting;
using Microsoft.AspNetCore.Hosting.Server.Features;
using Microsoft.AspNetCore.Hosting.Server;
using Microsoft.Extensions.Configuration;
using Microsoft.Extensions.DependencyInjection;
using Microsoft.Extensions.Hosting;
using Microsoft.Extensions.Logging;

namespace Certus.Web.Tests;

/// <summary>
/// The TLS floor on the HTTPS endpoint (issue #484, SEC-N1). The security agent
/// found the service completing TLS 1.0 and TLS 1.1 handshakes on lab 2025,
/// because nothing set <c>SslProtocols</c> and Kestrel left the choice to schannel.
///
/// <para>
/// Each test starts a real Kestrel on a loopback port, built the way
/// <c>Certus.Service/Program.cs</c> builds its endpoint: the <c>Https</c> endpoint
/// comes from configuration, and its certificate comes either from a configured
/// path (the self signed fallback and an administrator's PFX) or from code (the
/// certificate the wizard installed in the machine store). Both shapes are covered
/// because only the store shape configured HTTPS in code before the fix. These
/// tests need nothing but loopback, unlike the WebApplicationFactory hosts, so
/// they carry no Integration trait and the PR build runs them.
/// </para>
///
/// <para>
/// Two kinds of evidence, on purpose. The first reads the protocol set Kestrel
/// hands to SslStream, through the endpoint's <c>OnAuthenticate</c> hook, so it
/// holds on any operating system. The second is the handshake itself, which is
/// what the security agent measures, and it only proves something on a machine
/// whose schannel will still speak TLS 1.1 when asked. So it first shows that an
/// unpinned server does, and fails rather than passing vacuously when the machine
/// cannot.
/// </para>
/// </summary>
public sealed class HttpsProtocolPolicyTests : IDisposable
{
    private const string PfxPassword = "certus-test";

    // Bounds every handshake, so a regression reports instead of hanging the run.
    private static readonly TimeSpan HandshakeTimeout = TimeSpan.FromSeconds(30);

    private readonly string _directory;
    private readonly string _pfxPath;
    private readonly X509Certificate2 _certificate;

    public HttpsProtocolPolicyTests()
    {
        _directory = Path.Combine(Path.GetTempPath(), "certus-tls-" + Guid.NewGuid().ToString("N"));
        Directory.CreateDirectory(_directory);

        using var rsa = RSA.Create(2048);
        var request = new CertificateRequest(
            "CN=localhost", rsa, HashAlgorithmName.SHA256, RSASignaturePadding.Pkcs1);
        var san = new SubjectAlternativeNameBuilder();
        san.AddDnsName("localhost");
        request.CertificateExtensions.Add(san.Build());
        using var generated = request.CreateSelfSigned(
            DateTimeOffset.UtcNow.AddMinutes(-5), DateTimeOffset.UtcNow.AddDays(1));
        var pfx = generated.Export(X509ContentType.Pfx, PfxPassword);

        _pfxPath = Path.Combine(_directory, "server.pfx");
        File.WriteAllBytes(_pfxPath, pfx);

        // Reloaded from the PFX rather than used as generated: schannel cannot
        // serve the ephemeral key CreateSelfSigned returns.
        _certificate = X509CertificateLoader.LoadPkcs12(pfx, PfxPassword);
    }

    public void Dispose()
    {
        _certificate.Dispose();
        try { Directory.Delete(_directory, recursive: true); }
        catch (IOException) { }
        catch (UnauthorizedAccessException) { }
    }

    /// <summary>Where the served certificate comes from, as in Program.cs.</summary>
    public enum CertificateSource
    {
        /// <summary><c>Kestrel:Endpoints:Https:Certificate:Path</c>.</summary>
        ConfiguredPath,

        /// <summary>A certificate set in code from LocalMachine\My.</summary>
        Store,
    }

    [Theory]
    [InlineData(CertificateSource.ConfiguredPath)]
    [InlineData(CertificateSource.Store)]
    public async Task ServedEndpoint_HandsSslStreamOnlyTls12AndTls13(CertificateSource source)
    {
        await using var server = await StartAsync(source, pinned: true);

        var negotiated = await HandshakeAsync(server.Port, SslProtocols.Tls12);

        negotiated.Should().Be(SslProtocols.Tls12);
        server.Offered.Should().ContainSingle()
            .Which.Should().Be(SslProtocols.Tls12 | SslProtocols.Tls13,
                "the endpoint must offer TLS 1.2 and 1.3 and nothing the operating system adds");
    }

    [Theory]
    [InlineData(CertificateSource.ConfiguredPath)]
    [InlineData(CertificateSource.Store)]
    public async Task ServedEndpoint_RefusesTls10AndTls11AndStillNegotiatesTls12(CertificateSource source)
    {
#pragma warning disable SYSLIB0039 // TLS 1.0 and 1.1 are obsolete, which is the point of the test.
        const SslProtocols tls10 = SslProtocols.Tls;
        const SslProtocols tls11 = SslProtocols.Tls11;
#pragma warning restore SYSLIB0039

        // The control: the same endpoint without the floor. If this machine will
        // not negotiate TLS 1.1 even here, a refusal below would be the platform's
        // and not the floor's, so the test stops rather than passing on nothing.
        await using (var unpinned = await StartAsync(source, pinned: false))
        {
            var control = await HandshakeAsync(unpinned.Port, tls11);
            control.Should().Be(tls11,
                "this machine's schannel will not negotiate TLS 1.1 even for an unpinned " +
                "server, so a refusal below would be the platform's and prove nothing about " +
                "the floor. That is a host hardened in the SCHANNEL registry, or a Windows " +
                "release that turned TLS 1.1 off by default, not a defect in the product. " +
                "ServedEndpoint_HandsSslStreamOnlyTls12AndTls13 still guards the pin on any " +
                "host, and the live witness is then the security agent's section N probe " +
                "against a lab. Run this on a host that still offers TLS 1.1, or retire this " +
                "live half (issue #484)");
        }

        await using var server = await StartAsync(source, pinned: true);

        (await HandshakeAsync(server.Port, tls10)).Should().BeNull("TLS 1.0 is below the floor");
        (await HandshakeAsync(server.Port, tls11)).Should().BeNull("TLS 1.1 is below the floor");
        (await HandshakeAsync(server.Port, SslProtocols.Tls12)).Should().Be(SslProtocols.Tls12);
    }

    [Fact]
    public async Task EndpointDefaultsInConfiguration_CannotLowerTheFloor()
    {
        // Kestrel applies Kestrel:EndpointDefaults before the code defaults, so
        // the pin overwrites it. Only a protocol list on the endpoint itself wins.
        await using var server = await StartAsync(
            CertificateSource.ConfiguredPath, pinned: true,
            new Dictionary<string, string?> { ["Kestrel:EndpointDefaults:SslProtocols:0"] = "Tls11" });

        await HandshakeAsync(server.Port, SslProtocols.Tls12);

        server.Offered.Should().ContainSingle()
            .Which.Should().Be(SslProtocols.Tls12 | SslProtocols.Tls13);
    }

    [Fact]
    public async Task ProtocolsNamedOnTheEndpoint_OverrideTheFloor()
    {
        // The documented escape hatch: an administrator who names the protocols
        // on the endpoint gets exactly those. Pinned so the precedence the
        // HttpsProtocolPolicy remarks describe cannot change unnoticed.
        await using var server = await StartAsync(
            CertificateSource.ConfiguredPath, pinned: true,
            new Dictionary<string, string?> { ["Kestrel:Endpoints:Https:SslProtocols:0"] = "Tls12" });

        await HandshakeAsync(server.Port, SslProtocols.Tls12);

        server.Offered.Should().ContainSingle().Which.Should().Be(SslProtocols.Tls12);
    }

    [Theory]
    [InlineData("")]
    [InlineData("Tls12")]
    [InlineData("Tls11,Tls12")]
    [InlineData("tls13")]
    [InlineData("Bogus")]
    [InlineData("Tls12,Bogus")]
    public async Task Describe_ReportsExactlyTheProtocolsKestrelHandsSslStream(string named)
    {
        // The service logs what Describe returns on every start, as the field
        // witness of the floor. A log that disagreed with the server would be worse
        // than none, so each shape is checked against the set Kestrel really hands
        // SslStream: no list, a list that keeps the floor, one that lowers it, one
        // in the wrong case, and values Kestrel drops because they do not parse.
        var names = named.Split(',', StringSplitOptions.RemoveEmptyEntries);
        var settings = names
            .Select((name, index) => (Key: $"Kestrel:Endpoints:Https:SslProtocols:{index}", Value: name))
            .ToDictionary(pair => pair.Key, pair => (string?)pair.Value);

        await using var server = await StartAsync(CertificateSource.ConfiguredPath, pinned: true, settings);

        // Only to make Kestrel run its OnAuthenticate hook. Whether this handshake
        // succeeds depends on the set under test, so its result is not the point.
        await HandshakeAsync(server.Port, SslProtocols.Tls12 | SslProtocols.Tls13);

        var described = HttpsProtocolPolicy.Describe(server.App.Configuration);

        var endpoint = described.Should().ContainSingle().Which;
        endpoint.Name.Should().Be("Https");
        endpoint.NamedOnEndpoint.Should().Be(names.Length > 0);
        server.Offered.Should().ContainSingle()
            .Which.Should().Be(endpoint.Protocols,
                "the protocols the service logs must be the ones the endpoint offers");
    }

    [Fact]
    public void Describe_SkipsEndpointsThatAreNotHttps()
    {
        var configuration = new ConfigurationBuilder()
            .AddInMemoryCollection(new Dictionary<string, string?>
            {
                ["Kestrel:Endpoints:Http:Url"] = "http://0.0.0.0:5000",
                ["Kestrel:Endpoints:Https:Url"] = "HTTPS://0.0.0.0:5001",
            })
            .Build();

        HttpsProtocolPolicy.Describe(configuration).Should().Equal(
            new HttpsEndpointProtocols("Https", HttpsProtocolPolicy.Allowed, NamedOnEndpoint: false));
    }

#pragma warning disable SYSLIB0039 // TLS 1.0 and 1.1 are obsolete, which is what is being detected.
    [Theory]
    [InlineData(SslProtocols.Tls12, false)]
    [InlineData(SslProtocols.Tls13, false)]
    [InlineData(SslProtocols.Tls12 | SslProtocols.Tls13, false)]
    [InlineData(SslProtocols.None, true)]
    [InlineData(SslProtocols.Tls, true)]
    [InlineData(SslProtocols.Tls11 | SslProtocols.Tls12, true)]
    [InlineData(SslProtocols.Tls | SslProtocols.Tls12 | SslProtocols.Tls13, true)]
#pragma warning restore SYSLIB0039
    public void AdmitsBelowFloor_IsTrueForAnythingOlderThanTls12AndForTheOsDefault(
        SslProtocols protocols, bool expected)
    {
        // None counts: it hands the choice back to Windows, which is how SEC-N1
        // happened in the first place.
        HttpsProtocolPolicy.AdmitsBelowFloor(protocols).Should().Be(expected);
    }

    [Fact]
    public void BothHosts_RouteTheirHttpsDefaultsThroughThePolicy()
    {
        // The tests above prove the policy; this proves the hosts use it. The
        // service's Program.cs is a top level program no test can run, so without
        // this its call could be deleted with every test still green. And because
        // ConfigureHttpsDefaults keeps only its last delegate, a second call
        // anywhere would quietly replace the floor, so the policy must be the
        // only caller.
        var src = Path.Combine(FindRepositoryRoot(), "src");

        var unpinnedHosts = new[] { "Certus.Service", "Certus.Web" }
            .Where(host => !File.ReadAllText(Path.Combine(src, host, "Program.cs"))
                .Contains("HttpsProtocolPolicy.Apply(", StringComparison.Ordinal))
            .ToList();

        unpinnedHosts.Should().BeEmpty(
            "every host must pin the TLS floor on its HTTPS endpoint (issue #484)");

        var callers = Directory.EnumerateFiles(src, "*.cs", SearchOption.AllDirectories)
            .Where(path => !path.Contains($"{Path.DirectorySeparatorChar}bin{Path.DirectorySeparatorChar}")
                        && !path.Contains($"{Path.DirectorySeparatorChar}obj{Path.DirectorySeparatorChar}"))
            .Where(path => File.ReadAllText(path).Contains(".ConfigureHttpsDefaults(", StringComparison.Ordinal))
            .Select(path => Path.GetRelativePath(src, path).Replace('\\', '/'))
            .ToList();

        callers.Should().Equal(
            ["Certus.Web/Security/HttpsProtocolPolicy.cs"],
            "set HTTPS defaults through HttpsProtocolPolicy.Apply, which carries the certificate too");
    }

    [Fact]
    public void TheService_LogsTheProtocolsItServesAndWarnsBelowTheFloor()
    {
        // The service's Program.cs is a top level program no test can run, so this
        // is the only thing that notices if the boot line or its warning goes. The
        // Describe tests above prove what the line would say.
        var program = File.ReadAllText(
            Path.Combine(FindRepositoryRoot(), "src", "Certus.Service", "Program.cs"));

        program.Should().Contain("HttpsProtocolPolicy.Describe(app.Configuration)",
            "the service must log the TLS protocols each HTTPS endpoint serves (issue #484)");
        program.Should().Contain("HttpsProtocolPolicy.AdmitsBelowFloor(",
            "the service must warn when configuration lowers the TLS floor (issue #484)");
    }

    /// <summary>
    /// Walks up from the test assembly to the directory holding Certus.sln, and
    /// throws when there is none: a guard that passes because it found no source
    /// to read would defeat the point of it. The NoLabArtefactsTests pattern.
    /// </summary>
    private static string FindRepositoryRoot()
    {
        var directory = new DirectoryInfo(AppContext.BaseDirectory);
        while (directory is not null &&
               !File.Exists(Path.Combine(directory.FullName, "Certus.sln")))
        {
            directory = directory.Parent;
        }

        return directory?.FullName ?? throw new InvalidOperationException(
            $"Could not find Certus.sln walking up from {AppContext.BaseDirectory}.");
    }

    /// <summary>
    /// Start Kestrel with the service's endpoint shape. <paramref name="pinned"/>
    /// false reproduces the code before issue #484: the store certificate set in
    /// code, no protocols anywhere.
    /// </summary>
    private async Task<RunningServer> StartAsync(
        CertificateSource source,
        bool pinned,
        IDictionary<string, string?>? extraSettings = null)
    {
        var builder = WebApplication.CreateBuilder(new WebApplicationOptions
        {
            EnvironmentName = Environments.Production,
            ContentRootPath = _directory,
        });
        builder.Logging.ClearProviders();

        var settings = new Dictionary<string, string?>
        {
            ["Kestrel:Endpoints:Https:Url"] = "https://127.0.0.1:0",
        };
        if (source == CertificateSource.ConfiguredPath)
        {
            settings["Kestrel:Endpoints:Https:Certificate:Path"] = _pfxPath;
            settings["Kestrel:Endpoints:Https:Certificate:Password"] = PfxPassword;
        }
        foreach (var (key, value) in extraSettings ?? new Dictionary<string, string?>())
            settings[key] = value;
        builder.Configuration.AddInMemoryCollection(settings);

        var storeCertificate = source == CertificateSource.Store ? _certificate : null;
        var offered = new ConcurrentQueue<SslProtocols>();

        builder.WebHost.ConfigureKestrel(kestrel =>
        {
            if (pinned)
                HttpsProtocolPolicy.Apply(kestrel, storeCertificate);
            else if (storeCertificate is not null)
                kestrel.ConfigureHttpsDefaults(https => https.ServerCertificate = storeCertificate);

            // Runs after the defaults and the endpoint's own configuration, so it
            // sees exactly the protocol set SslStream is about to be given.
            kestrel.ConfigurationLoader!.Endpoint("Https", endpoint =>
                endpoint.HttpsOptions.OnAuthenticate =
                    (_, ssl) => offered.Enqueue(ssl.EnabledSslProtocols));
        });

        var app = builder.Build();
        app.MapGet("/", () => "ok");
        await app.StartAsync();

        var address = app.Services.GetRequiredService<IServer>()
            .Features.Get<IServerAddressesFeature>()!.Addresses.Single();
        return new RunningServer(app, new Uri(address).Port, offered);
    }

    /// <summary>
    /// A client handshake offering only <paramref name="offered"/>. Returns the
    /// negotiated protocol, or null when the server refused it.
    /// </summary>
    private static async Task<SslProtocols?> HandshakeAsync(int port, SslProtocols offered)
    {
        using var tcp = new TcpClient();
        await tcp.ConnectAsync(IPAddress.Loopback, port).WaitAsync(HandshakeTimeout);
        await using var ssl = new SslStream(tcp.GetStream(), leaveInnerStreamOpen: false);
        try
        {
            await ssl.AuthenticateAsClientAsync(new SslClientAuthenticationOptions
            {
                TargetHost = "localhost",
                EnabledSslProtocols = offered,
                RemoteCertificateValidationCallback = (_, _, _, _) => true,
            }).WaitAsync(HandshakeTimeout);
            return ssl.SslProtocol;
        }
        catch (AuthenticationException)
        {
            return null;
        }
        catch (IOException)
        {
            // A server that refuses the protocol may reset the connection
            // rather than answer with an alert.
            return null;
        }
    }

    private sealed record RunningServer(
        WebApplication App, int Port, ConcurrentQueue<SslProtocols> Offered) : IAsyncDisposable
    {
        public async ValueTask DisposeAsync()
        {
            await App.StopAsync();
            await App.DisposeAsync();
        }
    }
}
