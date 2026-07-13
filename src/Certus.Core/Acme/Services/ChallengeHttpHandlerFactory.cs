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
}
