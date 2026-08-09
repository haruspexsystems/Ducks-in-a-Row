namespace Certus.Core.Acme.Attestation;

/// <summary>
/// Thrown when a posted attestation object cannot be decoded into an
/// <see cref="AttestationEnvelope"/>. The message is safe to return to the
/// ACME client as the problem detail: it describes the malformation and
/// never echoes payload bytes.
/// </summary>
public sealed class AttestationParseException : Exception
{
    public AttestationParseException(string message)
        : base(message)
    {
    }

    public AttestationParseException(string message, Exception innerException)
        : base(message, innerException)
    {
    }
}
