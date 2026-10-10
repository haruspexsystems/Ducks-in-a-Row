using System.Formats.Asn1;
using System.Security.Cryptography.X509Certificates;

namespace Certus.Core.Tests.Adcs;

/// <summary>
/// The platform facts the subject handling rests on, measured here rather than
/// asserted in a comment (issue #297).
///
/// A distinguished name has two orders and they run opposite ways. The encoded
/// RDNSequence is written general to specific (C, S, L, O, OU, CN), which is the
/// X.500 convention. The string rendering reverses it, per RFC 4514 section 2.1,
/// so the same name displays specific to general and leads with the common name.
/// X509Certificate2.Subject is that rendering, not the encoded sequence.
///
/// From issue #230 until issue #297 the sanitizer, the common name parser and
/// three test files all said the opposite, that .Subject is a straight
/// passthrough of the encoding and so puts the CN last.
/// The reason that stood is worth keeping on the record, because it is a trap any
/// replacement test can fall into again: the constructor reverses on the way in
/// and .Subject reverses on the way out, so a name written as a string comes back
/// as the same string under both hypotheses. Every measurement taken of it round
/// tripped through exactly that pair and could not tell them apart. The test this
/// class replaces even asserted that the rendering did not start with "CN=",
/// which was true only because its own input string had been written C first.
///
/// So the first test below reads the raw DER, and nothing else here is allowed to
/// stand as the oracle for it. The rest measure the string APIs against that.
/// </summary>
public class X500NameOrderingTests
{
    private const string CountryOid = "2.5.4.6";
    private const string OrganizationOid = "2.5.4.10";
    private const string OrganizationalUnitOid = "2.5.4.11";
    private const string CommonNameOid = "2.5.4.3";

    /// <summary>
    /// A name written the way RFC 4514 writes one, and the way every subject
    /// string in this codebase is spelled: specific to general, common name
    /// first.
    /// </summary>
    private const string Written = "CN=leaf.example.com, O=Example, C=NL";

    [Fact]
    public void TheStringConstructorEncodesGeneralToSpecific()
    {
        // Read out of the bytes, not out of a string API. Every string reader in
        // this family is itself a candidate for the reversal being measured, so
        // using one as the oracle would repeat the mistake the class comment
        // records.
        var name = new X500DistinguishedName(Written);

        FirstEncodedRdnType(name.RawData).Should().Be(
            CountryOid,
            "the written name leads with the common name, so an encoder that did " +
            "not reverse would put 2.5.4.3 (commonName) on the wire first");
    }

    [Fact]
    public void TheDisplayRenderingIsTheReverseOfTheEncodedOrder()
    {
        var name = new X500DistinguishedName(Written);

        // The cancellation itself, stated once. This is the assertion the old
        // test made, and on its own it proves nothing: it holds whether both
        // directions reverse or neither does.
        name.Name.Should().Be(Written);

        // What separates the two. None renders the encoded order, Reversed
        // renders the RFC 4514 order, and .Name is the second of those.
        name.Decode(X500DistinguishedNameFlags.None).Should().StartWith(
            "C=", "the encoded order is general to specific");
        name.Decode(X500DistinguishedNameFlags.Reversed).Should().Be(name.Name);
    }

    [Fact]
    public void EnumerateRelativeDistinguishedNamesDefaultsToTheDisplayOrder()
    {
        // The reversed parameter defaults to true, so the no argument overload
        // does not walk the encoding. A test that means to read DER order has to
        // pass false, and reading this the other way is how a replacement for the
        // old test would have gone wrong in a new way.
        var name = new X500DistinguishedName(Written);

        AttributeTypes(name.EnumerateRelativeDistinguishedNames())
            .Should().Equal(CommonNameOid, OrganizationOid, CountryOid);
        AttributeTypes(name.EnumerateRelativeDistinguishedNames(reversed: false))
            .Should().Equal(CountryOid, OrganizationOid, CommonNameOid);
    }

    [Fact]
    public void TheBuilderTakesComponentsInDisplayOrder()
    {
        // Load bearing and written down nowhere until now, though two green tests
        // in DistinguishedNameParserTests already depend on it: the builder takes
        // its components in the order they are rendered, which is the reverse of
        // the order they are encoded.
        var builder = new X500DistinguishedNameBuilder();
        builder.AddOrganizationName("Example");
        builder.AddCommonName("leaf.example.com");

        var name = builder.Build();

        name.Name.Should().Be("O=Example, CN=leaf.example.com");
        AttributeTypes(name.EnumerateRelativeDistinguishedNames(reversed: false))
            .Should().Equal(CommonNameOid, OrganizationOid);
    }

    [Fact]
    public void AnAdcsShapedNameIsBuiltCommonNameFirstAndDisplaysCommonNameFirst()
    {
        // The recipe for a fixture that carries the shape a certificate authority
        // actually issues, and the whole point of issue #297 in one assertion.
        // Adding the common name first is what puts it last on the wire, and the
        // rendering then leads with it, which is the opposite of what the
        // sanitizer's comment claimed for four releases.
        var builder = new X500DistinguishedNameBuilder();
        builder.AddCommonName("leaf.example.com");
        builder.AddOrganizationalUnitName("IT");
        builder.AddOrganizationName("Example");
        builder.AddCountryOrRegion("NL");

        var name = builder.Build();

        // A collection literal rather than the params overload, so the reason
        // below is read as a reason and not as a fifth expected OID.
        AttributeTypes(name.EnumerateRelativeDistinguishedNames(reversed: false))
            .Should().Equal(
                new[] { CountryOid, OrganizationOid, OrganizationalUnitOid, CommonNameOid },
                "this is the general to specific encoding the X.500 convention asks for");
        FirstEncodedRdnType(name.RawData).Should().Be(CountryOid);
        name.Name.Should().StartWith(
            "CN=leaf.example.com,",
            "a general to specific encoding displays the common name first");
    }

    /// <summary>
    /// The attribute type OID of the first relative distinguished name in an
    /// encoded X.501 name, read straight out of the DER.
    ///
    /// Name ::= RDNSequence, RDNSequence ::= SEQUENCE OF
    /// RelativeDistinguishedName, RelativeDistinguishedName ::= SET OF
    /// AttributeTypeAndValue, and AttributeTypeAndValue ::= SEQUENCE { type
    /// OBJECT IDENTIFIER, value ANY }. So three reads reach the first type.
    /// </summary>
    private static string FirstEncodedRdnType(byte[] rawData)
    {
        var rdnSequence = new AsnReader(rawData, AsnEncodingRules.DER).ReadSequence();
        var firstRdn = rdnSequence.ReadSetOf();
        var attribute = firstRdn.ReadSequence();
        return attribute.ReadObjectIdentifier();
    }

    private static IReadOnlyList<string> AttributeTypes(
        IEnumerable<X500RelativeDistinguishedName> rdns) =>
        rdns.Select(rdn => rdn.GetSingleElementType().Value!).ToList();
}
