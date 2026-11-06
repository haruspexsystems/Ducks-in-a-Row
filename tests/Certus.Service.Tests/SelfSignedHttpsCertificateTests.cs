using System.Security.Cryptography;
using System.Security.Cryptography.X509Certificates;
using Certus.Core.Setup;
using Microsoft.AspNetCore.DataProtection;
using Microsoft.Extensions.Logging.Abstractions;

namespace Certus.Service.Tests;

/// <summary>
/// The self signed fallback certificate after issue #635: no PFX under a fixed
/// password in the data folder, a keyring encrypted file instead, regenerated
/// whenever it cannot be read, and the old file deleted on sight.
/// </summary>
public sealed class SelfSignedHttpsCertificateTests : IDisposable
{
    private static readonly DateTimeOffset Now = new(2026, 10, 21, 12, 0, 0, TimeSpan.Zero);

    private readonly string _dataDirectory =
        Path.Combine(Path.GetTempPath(), "ducks-selfsigned-tests-" + Guid.NewGuid().ToString("N"));
    private readonly EphemeralDataProtectionProvider _keyring = new();
    private readonly List<X509Certificate2> _certificates = [];

    private SelfSignedHttpsCertificate.Outcome Load(
        DateTimeOffset? now = null, IDataProtectionProvider? keyring = null)
    {
        var outcome = SelfSignedHttpsCertificate.Load(
            _dataDirectory, keyring ?? _keyring, now ?? Now, NullLogger.Instance);
        _certificates.Add(outcome.Certificate);
        return outcome;
    }

    [Fact]
    public void FirstLoad_GeneratesAServerCertificateAndWritesNoPfx()
    {
        var outcome = Load();

        outcome.Regenerated.Should().BeTrue();
        outcome.Certificate.Subject.Should().Be(MachineCertificateChoices.SelfSignedFallbackSubject);
        outcome.Certificate.HasPrivateKey.Should().BeTrue();
        outcome.Certificate.NotAfter.ToUniversalTime().Should().BeCloseTo(
            Now.AddYears(SelfSignedHttpsCertificate.LifetimeYears).UtcDateTime, TimeSpan.FromMinutes(1));
        outcome.Certificate.Extensions.OfType<X509EnhancedKeyUsageExtension>().Single()
            .EnhancedKeyUsages.Cast<Oid>().Select(o => o.Value).Should().Contain("1.3.6.1.5.5.7.3.1");

        File.Exists(outcome.Path).Should().BeTrue();
        Path.GetFileName(outcome.Path).Should().Be(SelfSignedHttpsCertificate.FileName);
        Directory.EnumerateFiles(_dataDirectory, "*.pfx").Should().BeEmpty();

        // The file is a Data Protection payload: not a PKCS#12 and not openable
        // with any password, the old fixed one included.
        var bytes = File.ReadAllBytes(outcome.Path);
        bytes[0].Should().NotBe(0x30, "a PKCS#12 starts with an ASN.1 SEQUENCE");
        var openWithTheOldPassword = () =>
            X509CertificateLoader.LoadPkcs12(bytes, "certus-dev", X509KeyStorageFlags.EphemeralKeySet);
        openWithTheOldPassword.Should().Throw<CryptographicException>();
    }

    [Fact]
    public void SecondLoad_SameKeyring_ReusesTheCertificate()
    {
        var first = Load();

        var second = Load();

        second.Regenerated.Should().BeFalse();
        second.Reason.Should().BeNull();
        second.Certificate.Thumbprint.Should().Be(first.Certificate.Thumbprint);
        second.Certificate.HasPrivateKey.Should().BeTrue();
    }

    [Fact]
    public void Load_AnotherKeyring_RegeneratesInsteadOfFailing()
    {
        // A data folder restored onto another machine, or the service moved to
        // another account: the file cannot be read, and the only right answer
        // for a fallback certificate is a new one.
        var first = Load();

        var elsewhere = Load(keyring: new EphemeralDataProtectionProvider());

        elsewhere.Regenerated.Should().BeTrue();
        elsewhere.Reason.Should().Contain("keyring");
        elsewhere.Certificate.Thumbprint.Should().NotBe(first.Certificate.Thumbprint);
    }

    [Fact]
    public void Load_WithinTheRenewalWindow_Regenerates()
    {
        var first = Load();
        var nearExpiry = Now.AddYears(SelfSignedHttpsCertificate.LifetimeYears)
            .AddDays(-(SelfSignedHttpsCertificate.RenewalWindowDays - 1));

        var renewed = Load(now: nearExpiry);

        renewed.Regenerated.Should().BeTrue();
        renewed.Reason.Should().Contain("expires");
        renewed.Certificate.Thumbprint.Should().NotBe(first.Certificate.Thumbprint);
    }

    [Fact]
    public void Load_CorruptFile_Regenerates()
    {
        Load();
        File.WriteAllBytes(Path.Combine(_dataDirectory, SelfSignedHttpsCertificate.FileName), [1, 2, 3]);

        var outcome = Load();

        outcome.Regenerated.Should().BeTrue();
    }

    [Fact]
    public void RemoveLegacyFile_FixedPasswordPfxPresent_DeletesIt()
    {
        Directory.CreateDirectory(_dataDirectory);
        var legacyPath = Path.Combine(_dataDirectory, SelfSignedHttpsCertificate.LegacyFileName);
        File.WriteAllBytes(legacyPath, [0x30, 0x82]);

        SelfSignedHttpsCertificate.RemoveLegacyFile(_dataDirectory, NullLogger.Instance).Should().BeTrue();

        File.Exists(legacyPath).Should().BeFalse("the file is a private key under a password every copy of the product knew");
        SelfSignedHttpsCertificate.RemoveLegacyFile(_dataDirectory, NullLogger.Instance)
            .Should().BeFalse("there is nothing left to remove");
    }

    [Fact]
    public void Load_DoesNotTouchTheLegacyFile_TheHostSweepsItOnEveryBoot()
    {
        // Load runs only when the fallback is served; the sweep must not depend
        // on that, so it is the host's call and Load leaves the file alone.
        Directory.CreateDirectory(_dataDirectory);
        var legacyPath = Path.Combine(_dataDirectory, SelfSignedHttpsCertificate.LegacyFileName);
        File.WriteAllBytes(legacyPath, [0x30, 0x82]);

        Load();

        File.Exists(legacyPath).Should().BeTrue();
    }

    public void Dispose()
    {
        foreach (var certificate in _certificates)
            certificate.Dispose();
        if (Directory.Exists(_dataDirectory))
            Directory.Delete(_dataDirectory, recursive: true);
    }
}
