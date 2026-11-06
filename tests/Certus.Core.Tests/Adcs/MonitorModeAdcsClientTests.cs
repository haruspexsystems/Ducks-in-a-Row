using Certus.Core.Adcs;
using Certus.Core.Configuration;
using Microsoft.Extensions.DependencyInjection;
using Microsoft.Extensions.Logging;
using Microsoft.Extensions.Logging.Abstractions;

namespace Certus.Core.Tests.Adcs;

/// <summary>
/// Monitor mode's last line (issue #470): the wrapper passes every read through and never
/// lets either CA write reach the client it wraps, whichever path built that client.
/// </summary>
public class MonitorModeAdcsClientTests
{
    /// <summary>
    /// The two writes the product makes. Every other <see cref="IAdcsClient"/> method is
    /// a read. A method added to the interface fails the classification test below until
    /// someone decides which it is, so a new write cannot pass through by default.
    /// </summary>
    private static readonly string[] Writes =
    [
        nameof(IAdcsClient.SubmitCertificateRequestAsync),
        nameof(IAdcsClient.RevokeCertificateAsync),
    ];

    private static readonly string[] Reads =
    [
        nameof(IAdcsClient.GetCaInfoAsync),
        nameof(IAdcsClient.GetTemplatesAsync),
        nameof(IAdcsClient.GetCertificateAsync),
        nameof(IAdcsClient.QueryCertificatesAsync),
        nameof(IAdcsClient.GetRequestStatusAsync),
        nameof(IAdcsClient.GetCaCertificateChainAsync),
    ];

    [Fact]
    public void EveryClientMethod_IsClassifiedAsReadOrWrite()
    {
        typeof(IAdcsClient).GetMethods().Select(m => m.Name)
            .Should().BeEquivalentTo(Writes.Concat(Reads),
                "a method added to IAdcsClient must be classified here, and a write must be refused by the wrapper");
    }

    [Fact]
    public async Task Submit_IsRefused_AndNeverReachesTheInnerClient()
    {
        var inner = Substitute.For<IAdcsClient>();
        var sut = Wrap(inner);

        var act = () => sut.SubmitCertificateRequestAsync("WebServer", [1, 2, 3]);

        (await act.Should().ThrowAsync<CaWriteRefusedException>())
            .Which.Message.Should().Contain("monitor mode");
        await inner.DidNotReceiveWithAnyArgs().SubmitCertificateRequestAsync(default!, default!, default);
    }

    [Fact]
    public async Task Revoke_IsRefused_AndNeverReachesTheInnerClient()
    {
        var inner = Substitute.For<IAdcsClient>();
        var sut = Wrap(inner);

        var act = () => sut.RevokeCertificateAsync("1a2b", 1);

        (await act.Should().ThrowAsync<CaWriteRefusedException>())
            .Which.Message.Should().Contain("monitor mode");
        await inner.DidNotReceiveWithAnyArgs().RevokeCertificateAsync(default!, default, default);
    }

    [Fact]
    public async Task Reads_PassThrough()
    {
        var inner = Substitute.For<IAdcsClient>();
        var sut = Wrap(inner);
        using var cts = new CancellationTokenSource();
        var query = new CertificateQuery();

        await sut.GetCaInfoAsync(cts.Token);
        await sut.GetTemplatesAsync(cts.Token);
        await sut.GetCertificateAsync(7, cts.Token);
        await sut.QueryCertificatesAsync(query, cts.Token);
        await sut.GetRequestStatusAsync(8, cts.Token);
        await sut.GetCaCertificateChainAsync(cts.Token);

        await inner.Received(1).GetCaInfoAsync(cts.Token);
        await inner.Received(1).GetTemplatesAsync(cts.Token);
        await inner.Received(1).GetCertificateAsync(7, cts.Token);
        await inner.Received(1).QueryCertificatesAsync(query, cts.Token);
        await inner.Received(1).GetRequestStatusAsync(8, cts.Token);
        await inner.Received(1).GetCaCertificateChainAsync(cts.Token);
    }

    [Fact]
    public async Task EveryRefusal_IsLoggedAtError()
    {
        // A refusal here means a caller got past every gate further out, so it is a
        // defect, and it has to be loud enough to be reported.
        var logger = Substitute.For<ILogger<MonitorModeAdcsClient>>();
        logger.IsEnabled(Arg.Any<LogLevel>()).Returns(true);
        var sut = new MonitorModeAdcsClient(Substitute.For<IAdcsClient>(), logger);

        await FluentActions.Awaiting(() => sut.SubmitCertificateRequestAsync("WebServer", [1]))
            .Should().ThrowAsync<CaWriteRefusedException>();
        await FluentActions.Awaiting(() => sut.RevokeCertificateAsync("1a2b", 1))
            .Should().ThrowAsync<CaWriteRefusedException>();

        logger.ReceivedCalls()
            .Count(c => c.GetMethodInfo().Name == nameof(ILogger.Log)
                && (LogLevel)c.GetArguments()[0]! == LogLevel.Error)
            .Should().Be(2);
    }

    [Fact]
    public void TheRefusal_IsNeitherAnOutageNorADenial()
    {
        // An outage tells every caller to try again shortly, so the ACME finalize would
        // hand the order back to ready for a client to retry for ever; a denial sends
        // an operator to the CA's Security tab. Neither is what happened.
        var refusal = new CaWriteRefusedException("revocation");

        refusal.Should().NotBeAssignableTo<InvalidOperationException>();
        refusal.Should().NotBeAssignableTo<UnauthorizedAccessException>();
        refusal.Should().NotBeAssignableTo<OperationCanceledException>();
        refusal.Operation.Should().Be("revocation");
    }

    [Fact]
    public async Task Factory_WrapsEveryClientItCreates()
    {
        var inner = Substitute.For<IAdcsClient>();
        var innerFactory = Substitute.For<IAdcsClientFactory>();
        innerFactory.Create("CA01\\Issuing").Returns(inner);
        var sut = new MonitorModeAdcsClientFactory(innerFactory, NullLogger<MonitorModeAdcsClient>.Instance);

        var client = sut.Create("CA01\\Issuing");

        client.Should().BeOfType<MonitorModeAdcsClient>().Which.Inner.Should().BeSameAs(inner);
        await FluentActions.Awaiting(() => client.SubmitCertificateRequestAsync("WebServer", [1]))
            .Should().ThrowAsync<CaWriteRefusedException>();
        await inner.DidNotReceiveWithAnyArgs().SubmitCertificateRequestAsync(default!, default!, default);
    }

    [Fact]
    public void Dispose_ReachesTheInnerClient()
    {
        // The real client holds COM objects, and every factory caller disposes what it
        // was given; the wrapper must not be where that stops.
        var inner = Substitute.For<IAdcsClient, IDisposable>();

        Wrap(inner).Dispose();

        ((IDisposable)inner).Received(1).Dispose();
    }

    [Fact]
    public void Guard_FullMode_LeavesEveryRegistrationAlone()
    {
        var services = new ServiceCollection();
        var client = new MockAdcsClient();
        services.AddSingleton<IAdcsClient>(client);
        services.AddSingleton<IAdcsClientFactory, MockAdcsClientFactory>();
        var before = services.ToList();

        services.AddMonitorModeCaWriteGuard(CertusInstanceMode.Full);

        services.Should().Equal(before);
    }

    [Fact]
    public void Guard_MonitorMode_WrapsTheInstanceFactoryAndTypeShapes()
    {
        var services = new ServiceCollection();
        services.AddLogging();
        var instance = new MockAdcsClient();
        services.AddSingleton<IAdcsClient>(instance);
        services.AddSingleton<IAdcsClient>(_ => new MockAdcsClient());
        services.AddSingleton<IAdcsClientFactory, MockAdcsClientFactory>();

        services.AddMonitorModeCaWriteGuard(CertusInstanceMode.Monitor);
        using var provider = services.BuildServiceProvider();

        var clients = provider.GetServices<IAdcsClient>().ToList();
        clients.Should().HaveCount(2).And.AllBeOfType<MonitorModeAdcsClient>();
        ((MonitorModeAdcsClient)clients[0]).Inner.Should().BeSameAs(instance);
        provider.GetRequiredService<IAdcsClientFactory>().Should().BeOfType<MonitorModeAdcsClientFactory>()
            .Which.Inner.Should().BeOfType<MockAdcsClientFactory>();
    }

    [Fact]
    public void Guard_MonitorMode_WithNothingToWrap_Throws()
    {
        // A call placed above the CA registrations would otherwise guard nothing and
        // say nothing.
        var services = new ServiceCollection();

        var act = () => services.AddMonitorModeCaWriteGuard(CertusInstanceMode.Monitor);

        act.Should().Throw<InvalidOperationException>().WithMessage("*after the CA client is registered*");
    }

    private static MonitorModeAdcsClient Wrap(IAdcsClient inner) =>
        new(inner, NullLogger<MonitorModeAdcsClient>.Instance);
}
