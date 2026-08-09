using System.Formats.Cbor;

namespace Certus.Core.Acme.Attestation;

/// <summary>
/// The decoded outer shape of a device-attest-01 attestation object
/// (draft-ietf-acme-device-attest-08 section 5): a CBOR map carrying the
/// format string and the format specific attestation statement. Clients
/// SHOULD omit the WebAuthn authData member but MAY include it, and future
/// revisions may add members, so parsing tolerates authData and any unknown
/// keys. The attestation statement is kept as raw CBOR: its schema belongs
/// to the format verifier, not to this envelope.
/// </summary>
public sealed class AttestationEnvelope
{
    /// <summary>The attestation format, the CBOR "fmt" member (e.g. "apple").</summary>
    public string Format { get; }

    /// <summary>The "attStmt" member as its raw CBOR encoding, always a map.</summary>
    public byte[] AttStmt { get; }

    private AttestationEnvelope(string format, byte[] attStmt)
    {
        Format = format;
        AttStmt = attStmt;
    }

    /// <summary>
    /// Parses the decoded bytes of a posted attestation object.
    /// </summary>
    /// <exception cref="AttestationParseException">
    /// The bytes are not a CBOR map, the map is missing "fmt" or "attStmt",
    /// or a member has the wrong shape.
    /// </exception>
    public static AttestationEnvelope Parse(byte[] attestationObject)
    {
        if (attestationObject is not { Length: > 0 })
            throw new AttestationParseException("The attestation object is empty.");

        try
        {
            // Lax conformance: real clients emit definite length CTAP style CBOR,
            // but nothing in the draft requires canonical form, so accept any
            // well formed encoding.
            var reader = new CborReader(attestationObject, CborConformanceMode.Lax);

            if (reader.PeekState() != CborReaderState.StartMap)
                throw new AttestationParseException("The attestation object is not a CBOR map.");
            reader.ReadStartMap();

            string? format = null;
            byte[]? attStmt = null;

            while (reader.PeekState() != CborReaderState.EndMap)
            {
                var key = reader.ReadTextString();
                switch (key)
                {
                    case "fmt":
                        format = reader.ReadTextString();
                        break;
                    case "attStmt":
                        if (reader.PeekState() != CborReaderState.StartMap)
                            throw new AttestationParseException(
                                "The attestation statement is not a CBOR map.");
                        attStmt = reader.ReadEncodedValue().ToArray();
                        break;
                    default:
                        // authData (which clients SHOULD omit but MAY send) and any
                        // member a future revision adds. The server MUST ignore them.
                        reader.SkipValue();
                        break;
                }
            }
            reader.ReadEndMap();

            if (reader.BytesRemaining != 0)
                throw new AttestationParseException(
                    "The attestation object has trailing data after the CBOR map.");
            if (string.IsNullOrEmpty(format))
                throw new AttestationParseException(
                    "The attestation object carries no format (\"fmt\") member.");
            if (attStmt is null)
                throw new AttestationParseException(
                    "The attestation object carries no attestation statement (\"attStmt\") member.");

            return new AttestationEnvelope(format, attStmt);
        }
        catch (Exception ex) when (ex is CborContentException or InvalidOperationException or FormatException)
        {
            throw new AttestationParseException("The attestation object is not well formed CBOR.", ex);
        }
    }
}
