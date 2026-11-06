using Certus.Core.Acme.Services;
using Certus.Core.Security;
using Microsoft.Extensions.Options;

namespace Certus.Core.Tests.Acme;

public class NonceServiceTests
{
    private const int AcmeRateLimitOptionsDefaultCap = 10_000;

    private readonly NonceService _sut = new(Options.Create(new AcmeRateLimitOptions()));

    [Fact]
    public void GenerateNonce_ReturnsNonEmpty()
    {
        var nonce = _sut.GenerateNonce();
        nonce.Should().NotBeNullOrEmpty();
    }

    [Fact]
    public void GenerateNonce_ReturnsUniqueValues()
    {
        var nonces = Enumerable.Range(0, 100)
            .Select(_ => _sut.GenerateNonce())
            .ToHashSet();

        nonces.Should().HaveCount(100);
    }

    [Fact]
    public void GenerateNonce_IsUrlSafe()
    {
        var nonce = _sut.GenerateNonce();

        nonce.Should().NotContain("+");
        nonce.Should().NotContain("/");
        nonce.Should().NotContain("=");
    }

    [Fact]
    public void ValidateAndConsume_ValidNonce_ReturnsTrue()
    {
        var nonce = _sut.GenerateNonce();
        _sut.ValidateAndConsume(nonce).Should().BeTrue();
    }

    [Fact]
    public void ValidateAndConsume_SameNonceTwice_ReturnsFalseOnSecondUse()
    {
        var nonce = _sut.GenerateNonce();

        _sut.ValidateAndConsume(nonce).Should().BeTrue();
        _sut.ValidateAndConsume(nonce).Should().BeFalse();
    }

    [Fact]
    public void ValidateAndConsume_UnknownNonce_ReturnsFalse()
    {
        _sut.ValidateAndConsume("totally-made-up-nonce").Should().BeFalse();
    }

    [Fact]
    public void ValidateAndConsume_Null_ReturnsFalse()
    {
        _sut.ValidateAndConsume(null!).Should().BeFalse();
    }

    [Fact]
    public void ValidateAndConsume_Empty_ReturnsFalse()
    {
        _sut.ValidateAndConsume("").Should().BeFalse();
    }

    [Fact]
    public void ActiveCount_TracksNonces()
    {
        var initial = _sut.ActiveCount;

        _sut.GenerateNonce();
        _sut.GenerateNonce();

        _sut.ActiveCount.Should().Be(initial + 2);
    }

    [Fact]
    public void ValidateAndConsume_ExpiredNonce_ReturnsFalse()
    {
        // A nonce that exists but is older than the max age must be rejected (RFC 8555 §7.2).
        var time = new TestTimeProvider();
        var service = new NonceService(AcmeRateLimitOptionsDefaultCap, time);
        var nonce = service.GenerateNonce();

        time.Now = time.Now.AddHours(2); // past the 1 hour max age

        service.ValidateAndConsume(nonce).Should().BeFalse();
    }

    [Fact]
    public void GenerateNonce_AfterCleanInterval_SweepsExpired()
    {
        var time = new TestTimeProvider();
        var service = new NonceService(AcmeRateLimitOptionsDefaultCap, time);
        service.GenerateNonce(); // N1 at T0

        // Advance past both the max age and the sweep interval, then generate again. The second
        // GenerateNonce triggers the time based sweep, which removes the now expired N1.
        time.Now = time.Now.AddHours(2);
        service.GenerateNonce(); // N2

        service.ActiveCount.Should().Be(1); // N1 swept, only N2 remains
    }

    [Fact]
    public void Defaults_HoldTenThousandNonces()
    {
        // The decision on issue #632: 10,000 entries, documented on the
        // configuration page. The options carry the number; the service reads it.
        new AcmeRateLimitOptions().MaxStoredNonces.Should().Be(10_000);
        _sut.MaxEntries.Should().Be(10_000);
    }

    [Fact]
    public void GenerateNonce_BeyondTheCap_NeverStoresMoreThanTheCap()
    {
        var service = new NonceService(maxEntries: 5);

        for (var i = 0; i < 50; i++)
            service.GenerateNonce();

        service.ActiveCount.Should().Be(5);
    }

    [Fact]
    public void GenerateNonce_BeyondTheCap_EvictsTheOldestFirst()
    {
        var service = new NonceService(maxEntries: 3);
        var first = service.GenerateNonce();
        var second = service.GenerateNonce();
        var third = service.GenerateNonce();

        var fourth = service.GenerateNonce(); // evicts the first

        service.ValidateAndConsume(first).Should().BeFalse("the oldest nonce was evicted");
        service.ValidateAndConsume(second).Should().BeTrue();
        service.ValidateAndConsume(third).Should().BeTrue();
        service.ValidateAndConsume(fourth).Should().BeTrue("the newest nonce always gets in");
    }

    [Fact]
    public void GenerateNonce_WithConsumeInLockstep_KeepsTheOrderQueueBounded()
    {
        // A client that uses every nonce it is given keeps the live count at
        // one, so a cap on the live count alone would never trim the insertion
        // order queue and it would grow with every request for ever.
        var service = new NonceService(maxEntries: 4);

        for (var i = 0; i < 1_000; i++)
            service.ValidateAndConsume(service.GenerateNonce()).Should().BeTrue();

        service.ActiveCount.Should().Be(0);
        // A fresh nonce after the churn still works, which fails if the queue
        // held stale entries that were evicted ahead of it.
        service.ValidateAndConsume(service.GenerateNonce()).Should().BeTrue();
    }

    [Fact]
    public void Cap_BelowOne_IsRaisedToOne()
    {
        // A store that holds nothing would refuse every signed request.
        new AcmeRateLimitOptions { MaxStoredNonces = 0 }.EffectiveMaxStoredNonces.Should().Be(1);
        new AcmeRateLimitOptions { MaxStoredNonces = -7 }.EffectiveMaxStoredNonces.Should().Be(1);

        var service = new NonceService(Options.Create(new AcmeRateLimitOptions { MaxStoredNonces = 0 }));
        service.MaxEntries.Should().Be(1);
        var nonce = service.GenerateNonce();
        service.ValidateAndConsume(nonce).Should().BeTrue();
    }

    /// <summary>A controllable clock so expiry and the sweep can be driven without real time.</summary>
    private sealed class TestTimeProvider : TimeProvider
    {
        public DateTimeOffset Now { get; set; } = DateTimeOffset.UtcNow;
        public override DateTimeOffset GetUtcNow() => Now;
    }
}
