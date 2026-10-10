using Certus.Core.Adcs;

namespace Certus.Core.Tests.Adcs;

/// <summary>
/// The msPKI-RA-Application-Policies reader (issue #213). ADCS packs a
/// template's CNG settings into this one attribute as backtick separated
/// triples; the product used to look for an "msPKI-Asymmetric-Algorithm"
/// attribute, which does not exist in the schema, and then guessed RSA.
///
/// Every literal below carries real U+0060 grave accents. They are invisible
/// in most diffs, so prefer the helpers over hand writing new ones.
/// </summary>
public class RaApplicationPoliciesTests
{
    /// <summary>
    /// The example printed in [MS-CRTD] 2.23.2, verbatim.
    /// </summary>
    private const string SpecExample =
        "msPKI-Asymmetric-Algorithm`PZPWSTR`RSA`msPKI-Hash-Algorithm`PZPWSTR`SHA1`" +
        "msPKI-Key-Usage`DWORD`2`msPKI-RA-Application-Policies`PZPWSTR`1.3.6.1.4.1.311.10.3.8`";

    /// <summary>
    /// The value QA read off the stock OCSPResponseSigning template on a live
    /// Server 2025 forest while filing issue #213. Its key security descriptor
    /// is an SDDL string, which is the value most likely to upset a naive
    /// split: it carries semicolons and parentheses.
    /// </summary>
    private const string LiveOcspResponseSigning =
        "msPKI-Asymmetric-Algorithm`PZPWSTR`RSA`msPKI-Hash-Algorithm`PZPWSTR`SHA1`" +
        "msPKI-Key-Security-Descriptor`PZPWSTR`D:P(A;;FA;;;BA)(A;;FA;;;SY)`msPKI-Key-Usage`DWORD`2`";

    [Fact]
    public void ReadsTheAlgorithmFromTheSpecExample()
    {
        RaApplicationPolicies.TryGetAsymmetricAlgorithm([SpecExample], out var algorithm)
            .Should().BeTrue();
        algorithm.Should().Be("RSA");
    }

    [Fact]
    public void ReadsTheAlgorithmPastAnSddlValue()
    {
        RaApplicationPolicies.TryGetAsymmetricAlgorithm([LiveOcspResponseSigning], out var algorithm)
            .Should().BeTrue();
        algorithm.Should().Be("RSA");
    }

    [Fact]
    public void ReadsAnEllipticCurveAlgorithmVerbatim()
    {
        // The whole point of the fix: an EC template must not read as RSA.
        RaApplicationPolicies.TryGetAsymmetricAlgorithm(
            ["msPKI-Asymmetric-Algorithm`PZPWSTR`ECDSA_P256`"], out var algorithm)
            .Should().BeTrue();
        algorithm.Should().Be("ECDSA_P256");
    }

    [Fact]
    public void ToleratesAMissingTrailingDelimiter()
    {
        // The format writes one after every value, but a value that has lost
        // it is still unambiguous, so read it rather than refuse it.
        RaApplicationPolicies.TryGetAsymmetricAlgorithm(
            ["msPKI-Asymmetric-Algorithm`PZPWSTR`ECDSA_P384"], out var algorithm)
            .Should().BeTrue();
        algorithm.Should().Be("ECDSA_P384");
    }

    [Fact]
    public void FindsTheAlgorithmWhereverItSitsAndWhateverItsCase()
    {
        RaApplicationPolicies.TryGetAsymmetricAlgorithm(
            ["msPKI-Hash-Algorithm`PZPWSTR`SHA256`mspki-asymmetric-algorithm`PZPWSTR`ECDSA_P521`"],
            out var algorithm)
            .Should().BeTrue();
        algorithm.Should().Be("ECDSA_P521");
    }

    [Fact]
    public void TrimsTheValue()
    {
        RaApplicationPolicies.TryGetAsymmetricAlgorithm(
            ["msPKI-Asymmetric-Algorithm`PZPWSTR`  RSA  `"], out var algorithm)
            .Should().BeTrue();
        algorithm.Should().Be("RSA");
    }

    [Fact]
    public void ReadsTheFirstValueThatParses()
    {
        // The attribute is multi valued under the other syntax, so a list can
        // legitimately mix shapes. Skip what does not parse rather than stop.
        RaApplicationPolicies.TryGetAsymmetricAlgorithm(
            ["1.3.6.1.4.1.311.10.3.8", SpecExample], out var algorithm)
            .Should().BeTrue();
        algorithm.Should().Be("RSA");
    }

    [Theory]
    // An OID list: the other syntax entirely, and it carries no algorithm.
    [InlineData("1.3.6.1.4.1.311.10.3.8")]
    // Triples that simply do not configure an algorithm.
    [InlineData("msPKI-Hash-Algorithm`PZPWSTR`SHA256`msPKI-Key-Usage`DWORD`2`")]
    // A token count that does not divide into threes: refuse the whole value
    // rather than read a misaligned triple and mistake a Type for a Value.
    [InlineData("msPKI-Asymmetric-Algorithm`PZPWSTR`")]
    [InlineData("msPKI-Hash-Algorithm`PZPWSTR`SHA256`msPKI-Asymmetric-Algorithm`PZPWSTR`")]
    // Present but empty: nothing was configured, which is not an answer.
    [InlineData("msPKI-Asymmetric-Algorithm`PZPWSTR``")]
    [InlineData("")]
    [InlineData("   ")]
    public void AnswersUnknownRatherThanGuessing(string value)
    {
        RaApplicationPolicies.TryGetAsymmetricAlgorithm([value], out var algorithm)
            .Should().BeFalse();
        algorithm.Should().BeNull();
    }

    [Fact]
    public void AnswersUnknownForNoValuesAtAll()
    {
        RaApplicationPolicies.TryGetAsymmetricAlgorithm(null, out var fromNull).Should().BeFalse();
        fromNull.Should().BeNull();

        RaApplicationPolicies.TryGetAsymmetricAlgorithm([], out var fromEmpty).Should().BeFalse();
        fromEmpty.Should().BeNull();
    }

    [Theory]
    // Version 1 and 2 predate CNG: [MS-CRTD] 2.23.1.
    [InlineData(null, null, false)]
    [InlineData(1, null, false)]
    [InlineData(2, null, false)]
    // Version 3 always carries the triples: [MS-CRTD] 2.23.2.
    [InlineData(3, null, true)]
    [InlineData(3, 0x100, true)]
    // Version 4 is decided by CT_FLAG_USE_LEGACY_PROVIDER (0x100).
    [InlineData(4, null, true)]
    [InlineData(4, 0x0, true)]
    [InlineData(4, 0x10, true)]
    [InlineData(4, 0x100, false)]
    [InlineData(4, 0x110, false)]
    // Anything ADCS grows later follows the version 4 rule rather than
    // falling back to a heuristic that cannot see an elliptic curve.
    [InlineData(5, 0x0, true)]
    [InlineData(5, 0x100, false)]
    public void SyntaxGateFollowsTheSpec(int? schemaVersion, int? privateKeyFlags, bool expected)
    {
        RaApplicationPolicies.UsesCngTripleSyntax(schemaVersion, privateKeyFlags)
            .Should().Be(expected);
    }
}
