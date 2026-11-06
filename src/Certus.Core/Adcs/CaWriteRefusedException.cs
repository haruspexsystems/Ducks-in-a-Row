namespace Certus.Core.Adcs;

/// <summary>
/// Thrown by <see cref="MonitorModeAdcsClient"/> when something asks a monitor mode
/// server to write to its CA (issue #470). Nothing reached the CA.
///
/// It derives from <see cref="Exception"/> alone, and that is deliberate. It must not be
/// a <see cref="CaUnavailableException"/> (an <see cref="InvalidOperationException"/>):
/// every caller reads that one as "try again shortly", so the ACME finalize would hand
/// the order back to ready and its client would retry for ever, and the automatic
/// renewal would mail the administrators about a CA outage that is not happening. Nor a
/// <see cref="CaAccessDeniedException"/>, whose message sends an operator to the CA's
/// Security tab. Thrown before any submit returns, it lands in the general arm of each
/// caller, which treats it as the failure it is without claiming anything reached the CA:
/// the finalize invalidates the order with no orphan reported, because no request id was
/// ever recorded. A test pins the base type.
/// </summary>
public sealed class CaWriteRefusedException : Exception
{
    public CaWriteRefusedException(string operation)
        : base(
            "This server runs in monitor mode, so it never writes to the certification " +
            $"authority. The {operation} was refused and nothing was sent to the CA.")
    {
        Operation = operation;
    }

    /// <summary>What was refused, in words: "certificate request" or "revocation".</summary>
    public string Operation { get; }
}
