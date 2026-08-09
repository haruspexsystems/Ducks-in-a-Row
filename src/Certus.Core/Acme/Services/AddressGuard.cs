using System.Net;
using System.Net.Sockets;
using Microsoft.Extensions.Options;

namespace Certus.Core.Acme.Services;

/// <summary>
/// Thrown when a challenge validation target resolves to an address that policy blocks.
/// This is a hard policy rejection, not a transient transport error, so the challenge
/// should be marked invalid rather than retried.
/// </summary>
public sealed class AddressBlockedException : Exception
{
    public AddressBlockedException(string host)
        : base($"Validation target '{host}' resolves to a blocked address.")
    {
    }
}

/// <summary>
/// Screens challenge validation targets so the HTTP-01 and TLS-ALPN-01 validators cannot
/// be pointed at loopback, link local, or other operator blocked addresses (a server side
/// request forgery). The resolved IP is vetted at connect time, which also defeats DNS
/// rebinding between order creation and validation. DNS-01 never connects to the target,
/// so it does not use this guard.
/// </summary>
public sealed class AddressGuard
{
    private readonly ChallengeValidationOptions _options;
    private readonly List<(byte[] Network, int PrefixLength)> _blockedCidrs;

    public AddressGuard(IOptions<ChallengeValidationOptions> options)
    {
        _options = options.Value;
        _blockedCidrs = ParseCidrs(_options.AdditionalBlockedCidrs);
    }

    /// <summary>
    /// True if a host literal is blocked without needing a DNS lookup. Used at order
    /// creation for a fast, resolution free rejection of obvious targets. The connect time
    /// vetting in <see cref="ResolveAndVetAsync"/> remains the real enforcement point.
    /// </summary>
    public bool IsBlockedLiteral(string host)
    {
        if (string.IsNullOrWhiteSpace(host))
            return false;
        if (host.Equals("localhost", StringComparison.OrdinalIgnoreCase))
            return true;
        return IPAddress.TryParse(host, out var ip) && IsBlocked(ip);
    }

    /// <summary>True if the address is blocked by the configured policy.</summary>
    public bool IsBlocked(IPAddress address)
    {
        var ip = address.IsIPv4MappedToIPv6 ? address.MapToIPv4() : address;

        if (_options.BlockLoopback && IPAddress.IsLoopback(ip))
            return true;
        if (_options.BlockLinkLocal && IsLinkLocal(ip))
            return true;
        if (_options.BlockUniqueLocalIpv6 && IsUniqueLocalIpv6(ip))
            return true;
        if (_options.BlockPrivateRanges && IsPrivateIpv4(ip))
            return true;

        foreach (var (network, prefixLength) in _blockedCidrs)
        {
            if (IsInCidr(ip, network, prefixLength))
                return true;
        }

        return false;
    }

    /// <summary>
    /// Resolves the host and returns a vetted address to connect to. Throws
    /// <see cref="AddressBlockedException"/> when the host is "localhost" or any resolved
    /// address is blocked. Rejecting on any blocked address stops an attacker from mixing a
    /// public and a private record and having the validator connect to the private one.
    /// </summary>
    public async ValueTask<IPAddress> ResolveAndVetAsync(string host, CancellationToken cancellationToken)
    {
        if (host.Equals("localhost", StringComparison.OrdinalIgnoreCase))
            throw new AddressBlockedException(host);

        IPAddress[] addresses = IPAddress.TryParse(host, out var literal)
            ? [literal]
            : await Dns.GetHostAddressesAsync(host, cancellationToken);

        if (addresses.Length == 0)
            throw new AddressBlockedException(host);

        foreach (var address in addresses)
        {
            if (IsBlocked(address))
                throw new AddressBlockedException(host);
        }

        return addresses[0];
    }

    private static bool IsLinkLocal(IPAddress ip)
    {
        if (ip.IsIPv6LinkLocal)
            return true;
        if (ip.AddressFamily == AddressFamily.InterNetwork)
        {
            var bytes = ip.GetAddressBytes();
            return bytes[0] == 169 && bytes[1] == 254; // 169.254.0.0/16
        }
        return false;
    }

    private static bool IsUniqueLocalIpv6(IPAddress ip)
    {
        if (ip.AddressFamily != AddressFamily.InterNetworkV6)
            return false;
        var bytes = ip.GetAddressBytes();
        return (bytes[0] & 0xFE) == 0xFC; // fc00::/7
    }

    private static bool IsPrivateIpv4(IPAddress ip)
    {
        if (ip.AddressFamily != AddressFamily.InterNetwork)
            return false;
        var bytes = ip.GetAddressBytes();
        return bytes[0] == 10                                // 10.0.0.0/8
            || (bytes[0] == 172 && (bytes[1] & 0xF0) == 16)  // 172.16.0.0/12
            || (bytes[0] == 192 && bytes[1] == 168);         // 192.168.0.0/16
    }

    private static List<(byte[] Network, int PrefixLength)> ParseCidrs(string[] cidrs)
    {
        var result = new List<(byte[], int)>();
        foreach (var entry in cidrs)
        {
            var slash = entry.IndexOf('/');
            if (slash < 0)
                throw new FormatException($"Invalid blocked CIDR '{entry}': expected address/prefix.");

            if (!IPAddress.TryParse(entry[..slash], out var network) ||
                !int.TryParse(entry[(slash + 1)..], out var prefix))
                throw new FormatException($"Invalid blocked CIDR '{entry}'.");

            var bytes = (network.IsIPv4MappedToIPv6 ? network.MapToIPv4() : network).GetAddressBytes();
            if (prefix < 0 || prefix > bytes.Length * 8)
                throw new FormatException($"Invalid blocked CIDR prefix in '{entry}'.");

            result.Add((bytes, prefix));
        }
        return result;
    }

    private static bool IsInCidr(IPAddress ip, byte[] network, int prefixLength)
    {
        var ipBytes = ip.GetAddressBytes();
        if (ipBytes.Length != network.Length)
            return false; // different address families never match

        int fullBytes = prefixLength / 8;
        int remainingBits = prefixLength % 8;

        for (int i = 0; i < fullBytes; i++)
        {
            if (ipBytes[i] != network[i])
                return false;
        }

        if (remainingBits > 0)
        {
            int mask = (0xFF << (8 - remainingBits)) & 0xFF;
            if ((ipBytes[fullBytes] & mask) != (network[fullBytes] & mask))
                return false;
        }

        return true;
    }
}
