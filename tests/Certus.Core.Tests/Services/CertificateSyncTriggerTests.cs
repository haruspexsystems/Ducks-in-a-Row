using Certus.Core.Services;

namespace Certus.Core.Tests.Services;

/// <summary>
/// Tests for the sync wake trigger: immediate fires, buffered fires, interval
/// timeout behavior, and debounce coalescing for ACME issuance bursts.
/// </summary>
public class CertificateSyncTriggerTests
{
    private static readonly TimeSpan LongWait = TimeSpan.FromSeconds(10);
    private static readonly TimeSpan ShortWait = TimeSpan.FromMilliseconds(100);

    [Fact]
    public async Task Fire_WakesAPendingWait()
    {
        var trigger = new CertificateSyncTrigger();
        var wait = trigger.WaitAsync(LongWait, CancellationToken.None);

        trigger.Fire();

        (await wait).Should().BeTrue();
    }

    [Fact]
    public async Task Fire_BeforeAnyWait_IsBufferedForTheNextWait()
    {
        var trigger = new CertificateSyncTrigger();

        trigger.Fire();

        (await trigger.WaitAsync(LongWait, CancellationToken.None)).Should().BeTrue();
    }

    [Fact]
    public async Task Wait_ReturnsFalseWhenTheTimeoutElapses()
    {
        var trigger = new CertificateSyncTrigger();

        (await trigger.WaitAsync(ShortWait, CancellationToken.None)).Should().BeFalse();
    }

    [Fact]
    public async Task Wait_ThrowsOnlyOnCallerCancellation()
    {
        var trigger = new CertificateSyncTrigger();
        using var cts = new CancellationTokenSource();
        cts.Cancel();

        var act = () => trigger.WaitAsync(LongWait, cts.Token);

        await act.Should().ThrowAsync<OperationCanceledException>();
    }

    [Fact]
    public async Task FireDebounced_CoalescesABurstIntoOneFire()
    {
        var trigger = new CertificateSyncTrigger();

        trigger.FireDebounced(TimeSpan.FromMilliseconds(50));
        trigger.FireDebounced(TimeSpan.FromMilliseconds(50));
        trigger.FireDebounced(TimeSpan.FromMilliseconds(50));

        // The burst produces exactly one fire...
        (await trigger.WaitAsync(LongWait, CancellationToken.None)).Should().BeTrue();

        // ...and nothing more is pending afterwards.
        (await trigger.WaitAsync(TimeSpan.FromMilliseconds(200), CancellationToken.None)).Should().BeFalse();
    }

    [Fact]
    public async Task FireDebounced_AfterTheWindowCloses_FiresAgain()
    {
        var trigger = new CertificateSyncTrigger();

        trigger.FireDebounced(TimeSpan.FromMilliseconds(20));
        (await trigger.WaitAsync(LongWait, CancellationToken.None)).Should().BeTrue();

        trigger.FireDebounced(TimeSpan.FromMilliseconds(20));
        (await trigger.WaitAsync(LongWait, CancellationToken.None)).Should().BeTrue();
    }
}
