using System.Net;
using System.Net.Sockets;

namespace Certus.Core.Acme.Services;

/// <summary>
/// Builds the primary HTTP message handler for the HTTP-01 validator. Redirects are
/// disabled by default and every connection is routed through <see cref="AddressGuard"/>,
/// so the validator cannot be redirected or rebound onto an internal address (a server
/// side request forgery).
/// </summary>
public static class ChallengeHttpHandlerFactory
{
    public static SocketsHttpHandler Create(AddressGuard guard, ChallengeValidationOptions options)
    {
        return new SocketsHttpHandler
        {
            // A challenge server must not be able to bounce the validator at an internal
            // address. Following redirects is opt in via configuration.
            AllowAutoRedirect = options.AllowRedirects,
            ConnectCallback = async (context, cancellationToken) =>
            {
                // Vet the port as well as the address (issue #345). The guard
                // reads the host and nothing else, so before this an identifier
                // that carried its own port, "10.0.0.5:22", sent the validator
                // to an arbitrary internal service and the answer told the
                // client whether it was listening. 80 is the port RFC 8555
                // section 8.3 makes the request on; 443 stays legal because the
                // same section permits a redirect to https, which AllowRedirects
                // turns on. Every other port is the primitive being closed.
                var port = context.DnsEndPoint.Port;
                if (!IsPermittedPort(port))
                    throw new AddressBlockedException(context.DnsEndPoint.Host, port);

                var ip = await guard.ResolveAndVetAsync(context.DnsEndPoint.Host, cancellationToken);
                var socket = new Socket(SocketType.Stream, ProtocolType.Tcp) { NoDelay = true };
                try
                {
                    await socket.ConnectAsync(
                        new IPEndPoint(ip, context.DnsEndPoint.Port), cancellationToken);
                    return new NetworkStream(socket, ownsSocket: true);
                }
                catch
                {
                    socket.Dispose();
                    throw;
                }
            }
        };
    }

    /// <summary>
    /// The ports challenge validation may open a connection on. 80 is the one
    /// RFC 8555 section 8.3 makes the http-01 request on. 443 is here because
    /// the same section permits the challenge server to redirect to https, and
    /// <see cref="ChallengeValidationOptions.AllowRedirects"/> lets an operator
    /// turn that on. Everything else is refused before the socket exists.
    /// </summary>
    public static bool IsPermittedPort(int port) => port is 80 or 443;
}
