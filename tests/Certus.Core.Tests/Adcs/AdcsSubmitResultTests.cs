using Certus.Adcs;
using Certus.Adcs.ComInterop;
using Certus.Core.Adcs;

namespace Certus.Core.Tests.Adcs;

/// <summary>
/// Tests for the submit result mapping in AdcsClient.
///
/// The submit itself needs a live CA, which is why the mapping and the sanitize
/// were split into an internal helper: this file is the whole test seam for what
/// the COM path does with the CA's answer, exactly as AdcsColumnMappingTests is
/// for what it does with a view row.
///
/// The sanitize is the point of the file (issue #362). The CA's disposition
/// message was the last CA authored string in the product to reach an ACME
/// problem document, the wizard, the settings page and the service log with
/// nothing stripping or bounding it, while the sync path in the same class has
/// run its copy of the same column through the sanitizer since issue #224.
/// </summary>
public class AdcsSubmitResultTests
{
    private const char Esc = (char)0x1b;
    private const char Lf = (char)0x0a;
    private const char LineSep = (char)0x2028;
    private const char Rlo = (char)0x202e;

    [Theory]
    [InlineData(DispositionCode.Issued, SubmitStatus.Issued)]
    [InlineData(DispositionCode.IssuedOutOfBand, SubmitStatus.Issued)]
    [InlineData(DispositionCode.UnderSubmission, SubmitStatus.Pending)]
    [InlineData(DispositionCode.Denied, SubmitStatus.Denied)]
    [InlineData(DispositionCode.Revoked, SubmitStatus.Error)]
    [InlineData(9999, SubmitStatus.Error)]
    public void BuildSubmitResult_MapsTheDisposition(int disposition, SubmitStatus expected)
    {
        // Error is the answer for anything unrecognized, which MockAdcsClient
        // deliberately matches for a request it cannot decode (issue #332).
        AdcsClient.BuildSubmitResult(7, disposition, "Issued")
            .Should().BeEquivalentTo(new { RequestId = 7, Status = expected });
    }

    [Fact]
    public void BuildSubmitResult_KeepsAnOrdinaryMessageWhole()
    {
        // What the lab CA actually answered for a template Enroll denial: the
        // bare string, no status code and no reason (request 109, 2026-08-24).
        AdcsClient.BuildSubmitResult(109, DispositionCode.Denied, "Denied by Policy Module")
            .Message.Should().Be("Denied by Policy Module");
    }

    [Fact]
    public void BuildSubmitResult_StripsDeceptiveCharactersFromTheMessage()
    {
        // A denial frequently quotes the subject name the CSR asked for, so a
        // substring of this is requester influenced. A bidirectional override
        // makes an operator read a different host than the one that was refused,
        // and U+2028 forges a line for any reader that honours it.
        var raw = Esc + "[31mDenied for " + Rlo + "moc.elpmaxe" + LineSep + "FATAL forged";

        AdcsClient.BuildSubmitResult(1, DispositionCode.Denied, raw)
            .Message.Should().Be("[31mDenied for moc.elpmaxeFATAL forged");
    }

    [Fact]
    public void BuildSubmitResult_KeepsRealLineBreaksForTheWireAndTheDashboard()
    {
        // The CA composes multi line messages and both the ACME problem document
        // and the certificate detail page render them, so these survive here. The
        // log is the surface that cannot have them, and it takes the flattened
        // form from SanitizeDispositionMessageForLog instead.
        var raw = "Error Constructing or Publishing Certificate" + Lf + "Invalid Request";

        AdcsClient.BuildSubmitResult(1, DispositionCode.Denied, raw)
            .Message.Should().Be(raw);
    }

    [Fact]
    public void BuildSubmitResult_BoundsAnOverLongMessage()
    {
        // The CA schema allows 8192 characters for this column and nothing further
        // down the chain bounds it: AcmeOrder.ErrorJson declares no width, SQLite
        // would not enforce one, and the problem document has no cap of its own.
        var raw = new string('x', 8192);

        var message = AdcsClient.BuildSubmitResult(1, DispositionCode.Denied, raw).Message;

        message.Should().NotBeNull();
        message!.Length.Should()
            .BeLessThanOrEqualTo(CertificateTextSanitizer.MaxDispositionMessageLength);
    }

    [Theory]
    [InlineData(null)]
    [InlineData("")]
    [InlineData("   ")]
    public void BuildSubmitResult_TurnsABlankMessageIntoNull(string? raw)
    {
        // So the "no reason given" fallbacks in OrderService and
        // TlsCertificateEnroller fire for a CA that answered with nothing. An
        // empty string is not null, so before this they rendered an empty field.
        AdcsClient.BuildSubmitResult(1, DispositionCode.Denied, raw)
            .Message.Should().BeNull();
    }

    #region Issue #356: which dispositions are worth asking the CA about

    [Theory]
    [InlineData(DispositionCode.Denied)]
    [InlineData(DispositionCode.Revoked)]
    [InlineData(9999)]
    public void IsRefusal_TrueForTheDispositionsThatCarryAReason(int disposition)
    {
        // Denied and everything unrecognized, which maps to Error. These are the
        // only two SubmitStatus values a caller reports a reason for, so they are
        // the only two worth a GetLastStatus round trip.
        AdcsClient.IsRefusal(disposition).Should().BeTrue();
    }

    [Theory]
    [InlineData(DispositionCode.Issued)]
    [InlineData(DispositionCode.IssuedOutOfBand)]
    [InlineData(DispositionCode.UnderSubmission)]
    public void IsRefusal_FalseForIssuedAndPending(int disposition)
    {
        // Pending is the one worth stating. It is not issued, so the literal
        // reading of issue #356 would have read the code here, but a held request
        // is waiting on a person rather than failing and has no reason to give.
        // Nothing consumes the code on a pending result either: both pending arms
        // write their own message about CA manager approval. A template with
        // CT_FLAG_PEND_ALL_REQUESTS answers every order this way, so reading it
        // would have cost one COM round trip per order for a discarded value.
        AdcsClient.IsRefusal(disposition).Should().BeFalse();
    }

    [Fact]
    public void BuildSubmitResult_CarriesTheStatusCodeThroughUntouched()
    {
        // The code is read by the caller rather than here, because reading it needs
        // the live CCertRequest instance and keeping this method free of the CA is
        // the whole reason it exists. So all this has to do is not lose it.
        AdcsClient.BuildSubmitResult(
                7, DispositionCode.Denied, "Denied by Policy Module",
                CaStatusCode.TemplateDenied)
            .StatusCode.Should().Be(CaStatusCode.TemplateDenied);
    }

    [Fact]
    public void BuildSubmitResult_NoStatusCode_LeavesItNull()
    {
        AdcsClient.BuildSubmitResult(7, DispositionCode.Denied, "Denied by Policy Module")
            .StatusCode.Should().BeNull();
    }

    #endregion
}
