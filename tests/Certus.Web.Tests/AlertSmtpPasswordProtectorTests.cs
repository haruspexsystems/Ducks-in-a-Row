using Certus.Core.Security;
using Microsoft.AspNetCore.DataProtection;

namespace Certus.Web.Tests;

/// <summary>
/// The SMTP password has its own Data Protection purpose since issue #635,
/// with a read path that still accepts the EAB purpose every saved password
/// used before, and a rewrite the save path applies to such a blob.
/// </summary>
public class AlertSmtpPasswordProtectorTests
{
    private readonly EphemeralDataProtectionProvider _provider = new();

    [Fact]
    public void Protect_WritesUnderTheSmtpPurpose_NotTheEabOne()
    {
        var sut = new SmtpPasswordProtector(_provider);
        var eab = new DataProtectionSecretProtector(_provider);

        var blob = sut.Protect("hunter2");

        sut.TryUnprotect(blob).Should().Be("hunter2");
        eab.TryUnprotect(blob).Should().BeNull("an SMTP blob must not read as an EAB secret");
        _provider.CreateProtector(SmtpPasswordProtector.Purpose).Unprotect(blob).Should().Be("hunter2");
    }

    [Fact]
    public void TryUnprotect_StillReadsABlobAnOlderVersionWroteUnderTheEabPurpose()
    {
        var legacyBlob = _provider.CreateProtector(DataProtectionSecretProtector.Purpose).Protect("hunter2");

        new SmtpPasswordProtector(_provider).TryUnprotect(legacyBlob).Should().Be("hunter2");
    }

    [Fact]
    public void Rewrite_MovesALegacyBlobToTheSmtpPurpose_AndLeavesACurrentOneAlone()
    {
        var sut = new SmtpPasswordProtector(_provider);
        var legacyBlob = _provider.CreateProtector(DataProtectionSecretProtector.Purpose).Protect("hunter2");
        var currentBlob = sut.Protect("hunter2");

        var rewritten = sut.Rewrite(legacyBlob);

        rewritten.Should().NotBe(legacyBlob);
        _provider.CreateProtector(SmtpPasswordProtector.Purpose).Unprotect(rewritten).Should().Be("hunter2");
        new DataProtectionSecretProtector(_provider).TryUnprotect(rewritten).Should().BeNull();
        sut.Rewrite(currentBlob).Should().BeSameAs(currentBlob);
    }

    [Theory]
    [InlineData("CfDJ8-not-a-real-protected-payload")]
    [InlineData("")]
    public void Rewrite_LeavesABlobNoPurposeReadsExactlyAsItWas(string blob)
    {
        // The keyring that cannot read it is the one that must keep refusing
        // it; a rewrite would hide a restored data folder behind a new blob.
        new SmtpPasswordProtector(_provider).Rewrite(blob).Should().BeSameAs(blob);
    }

    [Theory]
    [InlineData("CfDJ8-not-a-real-protected-payload")]
    [InlineData("not base64 at all!")]
    public void TryUnprotect_UnreadableBlob_ReturnsNull(string blob)
    {
        new SmtpPasswordProtector(_provider).TryUnprotect(blob).Should().BeNull();
    }
}
