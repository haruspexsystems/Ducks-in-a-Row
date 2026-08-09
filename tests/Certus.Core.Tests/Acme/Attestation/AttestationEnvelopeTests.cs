using System.Formats.Cbor;
using Certus.Core.Acme.Attestation;

namespace Certus.Core.Tests.Acme.Attestation;

/// <summary>
/// Tests for the attestation object envelope parser. The contract from
/// draft-ietf-acme-device-attest-08 section 5: the object is a CBOR map,
/// "fmt" and "attStmt" are required, authData and unknown members MUST be
/// ignored, and anything else is a parse failure with a client safe detail.
/// </summary>
public class AttestationEnvelopeTests
{
    private static byte[] Cbor(Action<CborWriter> write)
    {
        var writer = new CborWriter(CborConformanceMode.Lax);
        write(writer);
        return writer.Encode();
    }

    private static void WriteAttStmt(CborWriter writer)
    {
        writer.WriteTextString("attStmt");
        writer.WriteStartMap(1);
        writer.WriteTextString("x5c");
        writer.WriteStartArray(0);
        writer.WriteEndArray();
        writer.WriteEndMap();
    }

    private static byte[] WellFormed(string format = "apple") =>
        Cbor(w =>
        {
            w.WriteStartMap(2);
            w.WriteTextString("fmt");
            w.WriteTextString(format);
            WriteAttStmt(w);
            w.WriteEndMap();
        });

    [Fact]
    public void Parse_WellFormed_ReturnsFormatAndRawStatement()
    {
        var envelope = AttestationEnvelope.Parse(WellFormed());

        envelope.Format.Should().Be("apple");
        envelope.AttStmt.Should().NotBeEmpty();

        // The raw statement must re-parse as a CBOR map for the format verifier.
        new CborReader(envelope.AttStmt, CborConformanceMode.Lax)
            .PeekState().Should().Be(CborReaderState.StartMap);
    }

    [Fact]
    public void Parse_AuthDataAndUnknownMembers_AreTolerated()
    {
        // Clients SHOULD omit authData but MAY send it, and future revisions
        // may add members; the server MUST ignore them all.
        var attObj = Cbor(w =>
        {
            w.WriteStartMap(4);
            w.WriteTextString("fmt");
            w.WriteTextString("apple");
            WriteAttStmt(w);
            w.WriteTextString("authData");
            w.WriteByteString(new byte[8]);
            w.WriteTextString("futureMember");
            w.WriteInt32(7);
            w.WriteEndMap();
        });

        var envelope = AttestationEnvelope.Parse(attObj);

        envelope.Format.Should().Be("apple");
    }

    [Fact]
    public void Parse_MissingFmt_Throws()
    {
        var attObj = Cbor(w =>
        {
            w.WriteStartMap(1);
            WriteAttStmt(w);
            w.WriteEndMap();
        });

        var act = () => AttestationEnvelope.Parse(attObj);

        act.Should().Throw<AttestationParseException>().WithMessage("*format*");
    }

    [Fact]
    public void Parse_EmptyFmt_Throws()
    {
        var act = () => AttestationEnvelope.Parse(WellFormed(format: ""));

        act.Should().Throw<AttestationParseException>().WithMessage("*format*");
    }

    [Fact]
    public void Parse_MissingAttStmt_Throws()
    {
        var attObj = Cbor(w =>
        {
            w.WriteStartMap(1);
            w.WriteTextString("fmt");
            w.WriteTextString("apple");
            w.WriteEndMap();
        });

        var act = () => AttestationEnvelope.Parse(attObj);

        act.Should().Throw<AttestationParseException>().WithMessage("*attestation statement*");
    }

    [Fact]
    public void Parse_AttStmtNotAMap_Throws()
    {
        var attObj = Cbor(w =>
        {
            w.WriteStartMap(2);
            w.WriteTextString("fmt");
            w.WriteTextString("apple");
            w.WriteTextString("attStmt");
            w.WriteTextString("not a map");
            w.WriteEndMap();
        });

        var act = () => AttestationEnvelope.Parse(attObj);

        act.Should().Throw<AttestationParseException>().WithMessage("*statement is not a CBOR map*");
    }

    [Fact]
    public void Parse_TopLevelNotAMap_Throws()
    {
        var attObj = Cbor(w =>
        {
            w.WriteStartArray(1);
            w.WriteInt32(1);
            w.WriteEndArray();
        });

        var act = () => AttestationEnvelope.Parse(attObj);

        act.Should().Throw<AttestationParseException>().WithMessage("*not a CBOR map*");
    }

    [Fact]
    public void Parse_NonTextKey_Throws()
    {
        var attObj = Cbor(w =>
        {
            w.WriteStartMap(1);
            w.WriteInt32(1);
            w.WriteInt32(2);
            w.WriteEndMap();
        });

        var act = () => AttestationEnvelope.Parse(attObj);

        act.Should().Throw<AttestationParseException>();
    }

    [Fact]
    public void Parse_TrailingData_Throws()
    {
        var attObj = WellFormed().Concat(new byte[] { 0x00 }).ToArray();

        var act = () => AttestationEnvelope.Parse(attObj);

        act.Should().Throw<AttestationParseException>().WithMessage("*trailing*");
    }

    [Fact]
    public void Parse_NotCbor_Throws()
    {
        // 0xFF is a CBOR break byte with no enclosing indefinite item.
        var act = () => AttestationEnvelope.Parse(new byte[] { 0xFF });

        act.Should().Throw<AttestationParseException>();
    }

    [Fact]
    public void Parse_Empty_Throws()
    {
        var act = () => AttestationEnvelope.Parse(Array.Empty<byte>());

        act.Should().Throw<AttestationParseException>().WithMessage("*empty*");
    }
}
