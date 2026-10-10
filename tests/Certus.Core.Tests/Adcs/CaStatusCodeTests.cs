using Certus.Core.Adcs;

namespace Certus.Core.Tests.Adcs;

/// <summary>
/// Unit tests for the CA status code map (issue #356).
///
/// The live <c>ICertRequest::GetLastStatus</c> call cannot be exercised without a
/// CA that denies the service account, the same limitation
/// <see cref="CaAccessDeniedExceptionTests"/> works around, so these pin the seam
/// either side of it: that a code the CA hands back is spelled the way an operator
/// can act on, and that the descriptions attached to the codes are the right ones.
///
/// That second half is the reason this file exists rather than a couple of
/// assertions bolted onto the consumers. A wrong entry in the map is worse than a
/// missing one, because a missing code still surfaces as hex while a wrong one
/// confidently misdescribes what the CA did.
/// </summary>
public class CaStatusCodeTests
{
    /// <summary>
    /// The value as COM actually delivers it. GetLastStatus returns a signed LONG,
    /// so every one of these arrives negative, and a test that wrote them as
    /// unsigned would not be testing the shape the product meets.
    /// </summary>
    private const int TemplateDeniedFromCom = unchecked((int)0x80094012);

    [Fact]
    public void Format_TheSignedValueComDelivers_ProducesTheUnsignedSpelling()
    {
        TemplateDeniedFromCom.Should().BeNegative(
            "the CA records the HRESULT signed, which is the whole reason Format exists");

        CaStatusCode.Format(TemplateDeniedFromCom).Should().Be("0x80094012",
            "this is the spelling an operator searches for and hands to certutil -error, " +
            "and the spelling the dashboard's formatHResult already produces for the same " +
            "value read out of the CA view");
    }

    [Fact]
    public void KnownCodes_AreAllEightDigitCertsrvFacilityCodes()
    {
        // Touching the collection also proves the map's initializer ran, which is
        // where a duplicated key would throw.
        CaStatusCode.KnownCodes.Should().NotBeEmpty();

        foreach (var code in CaStatusCode.KnownCodes)
        {
            var formatted = CaStatusCode.Format(code);
            formatted.Should().MatchRegex("^0x8009[0-9A-F]{4}$",
                $"every entry must be a CERTSRV facility HRESULT, and {formatted} is not");
        }
    }

    [Fact]
    public void KnownCodes_EachCarriesADescriptionThatReadsAsASentence()
    {
        foreach (var code in CaStatusCode.KnownCodes)
        {
            var description = CaStatusCode.Describe(code);
            description.Should().NotBeNullOrWhiteSpace();
            description!.Should().EndWith(".",
                "the descriptions are joined onto the CA's own message as prose, so one " +
                "that did not finish its sentence would run into whatever follows it");
        }
    }

    [Fact]
    public void Describe_TheCodeTheIssueGotWrong_IsNotInTheMap()
    {
        // Issue #356 as filed recorded CERTSRV_E_SUBJECT_EMAIL_REQUIRED as 0x80094003
        // and glossed it as "the template demands a name the CSR lacks". 0x80094003 is
        // really CERTSRV_E_BAD_REQUESTSTATUS, "the request's current status does not
        // allow this operation", which is not a submit time denial reason at all. The
        // row was dropped rather than corrected in place, and this is what stops it
        // being reintroduced from the issue text by someone working from the table.
        CaStatusCode.Describe(unchecked((int)0x80094003)).Should().BeNull(
            "0x80094003 is CERTSRV_E_BAD_REQUESTSTATUS and describes nothing about a denial");

        CaStatusCode.SubjectEmailRequired.Should().Be(unchecked((int)0x80094812),
            "0x80094812 is the value Windows actually uses for the email requirement");
        CaStatusCode.Describe(CaStatusCode.SubjectEmailRequired).Should()
            .Contain("EMail name is unavailable");
    }

    [Fact]
    public void Describe_TheCodeIssue194Cost_NamesTheTemplateProblem()
    {
        // The case that motivated the whole thing. A display name reached the CA where
        // a programmatic name was needed, the CA answered 0x80094800, ACME issued fine
        // against the same template, and the diagnosis cost a lab round trip because
        // nothing in the product ever named the code.
        CaStatusCode.UnsupportedCertType.Should().Be(unchecked((int)0x80094800));
        CaStatusCode.Describe(CaStatusCode.UnsupportedCertType).Should()
            .Contain("template is not supported by this CA");
    }

    [Fact]
    public void Describe_ACodeTheMapDoesNotName_IsNull()
    {
        // ADCS policy modules are pluggable, so a third party one may record codes of
        // its own. Null is the ordinary answer for those, not a failure.
        CaStatusCode.Describe(unchecked((int)0x8009FFFF)).Should().BeNull();
    }

    [Theory]
    [InlineData(null)]
    [InlineData(0)]
    public void Explain_NothingRecorded_IsNull(int? code)
    {
        // Zero is not reason zero. GetLastStatus answers S_OK after a call that
        // succeeded and the CA view records zero on an issued row, so both readings of
        // the same value have to agree that it carries no information.
        CaStatusCode.Explain(code).Should().BeNull();
    }

    [Fact]
    public void Explain_AMappedCode_LeadsWithTheHexAndFinishesTheSentence()
    {
        CaStatusCode.Explain(TemplateDeniedFromCom).Should().Be(
            "0x80094012: The permissions on the certificate template do not allow the " +
            "current user to enroll for this type of certificate.");
    }

    [Fact]
    public void Explain_AnUnmappedCode_StillNamesTheCodeInWords()
    {
        // The fallback is the reason a partial map is worth having. Even a code nobody
        // has described gives the operator something to search for, which is strictly
        // more than the bare disposition message gave.
        var explained = CaStatusCode.Explain(unchecked((int)0x8009FFFF));

        explained.Should().StartWith("0x8009FFFF",
            "leading with the hex keeps the value clear of the trailing full stop, so " +
            "it survives being copied into certutil -error");
        explained.Should().EndWith(".");
    }

    [Fact]
    public void DescribeRefusal_TheLabCase_TurnsABareDecisionIntoAReason()
    {
        // The exact string the manual2025 CA answered a template Enroll denial with on
        // 2026-08-24, request 109. This one assertion is the issue.
        CaStatusCode.DescribeRefusal("Denied by Policy Module", TemplateDeniedFromCom)
            .Should().Be(
                "Denied by Policy Module. 0x80094012: The permissions on the certificate " +
                "template do not allow the current user to enroll for this type of " +
                "certificate.");
    }

    [Fact]
    public void DescribeRefusal_AMessageThatAlreadyEndsASentence_GainsNoSecondFullStop()
    {
        CaStatusCode.DescribeRefusal("The request was refused.", TemplateDeniedFromCom)
            .Should().StartWith("The request was refused. 0x80094012:");
    }

    [Fact]
    public void DescribeRefusal_NoCode_IsTheCaMessageAlone()
    {
        // A policy module that says nothing useful is still the CA's own account, and
        // the explanation was only ever meant to travel beside it rather than replace
        // it. A module that does explain itself keeps its own words.
        CaStatusCode.DescribeRefusal("Denied by Policy Module", null)
            .Should().Be("Denied by Policy Module",
                "byte identical, not merely unparaphrased. Punctuation is added only " +
                "at a boundary this method creates, and with nothing to join there is " +
                "no boundary; issue #362 pins the same value on the ACME wire with Be " +
                "rather than Contain for exactly this reason");
    }

    [Fact]
    public void DescribeRefusal_NoMessage_IsTheExplanationAlone()
    {
        CaStatusCode.DescribeRefusal(null, TemplateDeniedFromCom)
            .Should().StartWith("0x80094012:");
    }

    [Theory]
    [InlineData(null)]
    [InlineData("")]
    [InlineData("   ")]
    public void DescribeRefusal_NeitherMessageNorCode_IsNull(string? message)
    {
        // Null rather than a wording of its own, so each caller keeps the fallback that
        // suits its surface: the wizard says "no reason given", the finalize says the
        // request was denied by the CA.
        CaStatusCode.DescribeRefusal(message, null).Should().BeNull();
        CaStatusCode.DescribeRefusal(message, 0).Should().BeNull();
    }

    [Fact]
    public void DescribeRefusal_NamesNoAccountAndNoHost()
    {
        // Why these may go on the ACME wire when OrderService.DescribeDenialRemedy may
        // not. That remedy names this service's own computer account, so PR #355 kept
        // it off the wire; Microsoft's descriptions name nobody, which is what makes
        // the wire answer safe here.
        foreach (var code in CaStatusCode.KnownCodes)
        {
            var explained = CaStatusCode.Explain(code)!;
            explained.Should().NotContain(Environment.MachineName);
            explained.Should().NotContain("$",
                "a computer account is spelled with a trailing dollar, and none belongs here");
        }
    }
}
