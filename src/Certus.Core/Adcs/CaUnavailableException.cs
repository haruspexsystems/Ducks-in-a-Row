using System.Runtime.InteropServices;

namespace Certus.Core.Adcs;

/// <summary>
/// Thrown when the ADCS Certificate Authority cannot be reached over RPC,
/// typically because CertSvc is stopped or the CA host is offline.
/// Inherits from InvalidOperationException so existing catch sites match,
/// but lets controllers return 503 Service Unavailable specifically.
/// </summary>
public sealed class CaUnavailableException : InvalidOperationException
{
    public const int RpcServerUnavailableHResult = unchecked((int)0x800706BA);

    public CaUnavailableException(string message)
        : base(message) { }

    public CaUnavailableException(string message, Exception inner)
        : base(message, inner) { }

    public static bool IsRpcUnavailable(COMException ex)
        => ex.HResult == RpcServerUnavailableHResult;
}
