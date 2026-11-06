using Certus.Core.Setup;
using Microsoft.Extensions.FileProviders;
using Microsoft.Extensions.Hosting;

namespace Certus.Core.Tests.Modules;

/// <summary>A host lifetime whose ApplicationStarted a test fires by hand.</summary>
internal sealed class FakeHostApplicationLifetime : IHostApplicationLifetime
{
    private readonly CancellationTokenSource _started = new();
    private readonly CancellationTokenSource _stopping = new();
    private readonly CancellationTokenSource _stopped = new();

    public CancellationToken ApplicationStarted => _started.Token;
    public CancellationToken ApplicationStopping => _stopping.Token;
    public CancellationToken ApplicationStopped => _stopped.Token;

    public void StopApplication() => _stopping.Cancel();

    public void FireStarted() => _started.Cancel();
}

/// <summary>A host environment a test can set to Production or Development.</summary>
internal sealed class FakeHostEnvironment : IHostEnvironment
{
    public string EnvironmentName { get; set; } = Environments.Production;
    public string ApplicationName { get; set; } = "Certus.Tests";
    public string ContentRootPath { get; set; } = AppContext.BaseDirectory;
    public IFileProvider ContentRootFileProvider { get; set; } = new NullFileProvider();
}

/// <summary>A restarter that counts how often a retry asked for one.</summary>
internal sealed class FakeServiceRestarter : IServiceRestarter
{
    public int Requests { get; private set; }

    public bool TryScheduleRestart()
    {
        Requests++;
        return true;
    }
}
