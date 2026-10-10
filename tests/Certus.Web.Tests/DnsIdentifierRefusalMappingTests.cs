using Certus.Core.Acme.Models;
using Certus.Web.Controllers.Acme;
using FluentAssertions;

namespace Certus.Web.Tests;

/// <summary>
/// The controller half of issue #345: each kind of dns identifier refusal
/// reaches the client as the ACME error RFC 8555 section 6.7 defines for it.
/// The grammar itself is proved in Certus.Core.Tests; this file proves what
/// each refusal then becomes on the wire.
///
/// A mapping test rather than an integration test, deliberately, and for the
/// same reason <see cref="FinalizeRefusalMappingTests"/> is one: the
/// integration tests that drive new-order boot a host and carry the
/// Integration trait, which CI filters out. This runs on the pull request
/// runner.
/// </summary>
public class DnsIdentifierRefusalMappingTests
{
    [Theory]
    // Not a host name at all. The client sent something this server cannot
    // read as an identifier, which is what malformed is for, and it matches
    // what the device branch answers for a permanent-identifier that fails its
    // own grammar.
    [InlineData(DnsIdentifierRefusalKind.Malformed, "urn:ietf:params:acme:error:malformed")]
    // A well-formed address. Nothing is wrong with the syntax; this server
    // issues for host names. Same disposition as the blocked literal screen
    // sitting next to it in the loop, which is where 127.0.0.1 has always been
    // answered.
    [InlineData(DnsIdentifierRefusalKind.IpLiteral, "urn:ietf:params:acme:error:rejectedIdentifier")]
    public void EachRefusalKind_MapsToItsAcmeError(
        DnsIdentifierRefusalKind kind, string expectedType)
    {
        OrderController.MapDnsIdentifierRefusal(kind).Should().Be(expectedType);
    }

    [Fact]
    public void EveryKind_IsMapped()
    {
        // The guard on the no-catch-all arm. A kind added later with no mapping
        // fails here rather than quietly answering whichever error happened to
        // be last in the switch.
        foreach (var kind in Enum.GetValues<DnsIdentifierRefusalKind>())
        {
            var map = () => OrderController.MapDnsIdentifierRefusal(kind);

            map.Should().NotThrow(
                "every refusal needs an ACME answer, and {0} has none", kind);
        }
    }

    [Fact]
    public void NoKindIsMappedToAnUnknownErrorType()
    {
        var known = new[] { AcmeErrorType.Malformed, AcmeErrorType.RejectedIdentifier };

        foreach (var kind in Enum.GetValues<DnsIdentifierRefusalKind>())
        {
            known.Should().Contain(
                OrderController.MapDnsIdentifierRefusal(kind),
                $"{kind} answers with a known error type");
        }
    }

    [Fact]
    public void AGrammarRefusalIsNeverAPolicyRefusal()
    {
        // The line the device path drew first and this one follows: a value the
        // grammar cannot read is not a decision the administrator's policy
        // made, so it must not answer as one. Reversing this would tell a
        // client to go and change a setting that has nothing to do with the
        // problem.
        OrderController.MapDnsIdentifierRefusal(DnsIdentifierRefusalKind.Malformed)
            .Should().NotBe(AcmeErrorType.RejectedIdentifier);
    }
}
