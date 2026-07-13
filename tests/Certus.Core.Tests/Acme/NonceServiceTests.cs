using Certus.Core.Acme.Services;

namespace Certus.Core.Tests.Acme;

public class NonceServiceTests
{
    private readonly NonceService _sut = new();

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
        var service = new NonceService(time);
        var nonce = service.GenerateNonce();

        time.Now = time.Now.AddHours(2); // past the 1 hour max age

        service.ValidateAndConsume(nonce).Should().BeFalse();
    }

    [Fact]
    public void GenerateNonce_AfterCleanInterval_SweepsExpired()
    {
        var time = new TestTimeProvider();
        var service = new NonceService(time);
        service.GenerateNonce(); // N1 at T0

        // Advance past both the max age and the sweep interval, then generate again. The second
        // GenerateNonce triggers the time based sweep, which removes the now expired N1.
        time.Now = time.Now.AddHours(2);
        service.GenerateNonce(); // N2

        service.ActiveCount.Should().Be(1); // N1 swept, only N2 remains
    }

    /// <summary>A controllable clock so expiry and the sweep can be driven without real time.</summary>
    private sealed class TestTimeProvider : TimeProvider
    {
        public DateTimeOffset Now { get; set; } = DateTimeOffset.UtcNow;
        public override DateTimeOffset GetUtcNow() => Now;
    }
}
