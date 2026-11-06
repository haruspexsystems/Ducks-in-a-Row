using System.Security.Cryptography;
using Microsoft.AspNetCore.DataProtection;

namespace Certus.Core.Security;

/// <summary>
/// <see cref="ISecretProtector"/> over ASP.NET Data Protection, for the EAB
/// secrets. The hosts persist the keyring to a "keys" folder next to the
/// database and protect it with DPAPI under the service account on Windows,
/// so backups of the data directory carry the keyring but a restore onto a
/// different machine, or under a different account, cannot decrypt it. That
/// failure surfaces here as <see cref="TryUnprotect"/> returning null; the
/// recovery is regenerating the credential secret (the key id and its
/// configuration are plaintext columns and survive). The saved SMTP password
/// has its own purpose in <see cref="SmtpPasswordProtector"/> (issue #635).
/// </summary>
public sealed class DataProtectionSecretProtector : ISecretProtector
{
    /// <summary>
    /// The protector purpose string. Versioned so a future format change can
    /// introduce a new purpose without breaking values written under this one.
    /// Before issue #635 the SMTP password was written under it too, which is
    /// why <see cref="SmtpPasswordProtector"/> still reads it.
    /// </summary>
    public const string Purpose = "Certus.Eab.v1";

    private readonly IDataProtector _protector;

    public DataProtectionSecretProtector(IDataProtectionProvider provider)
    {
        _protector = provider.CreateProtector(Purpose);
    }

    public string Protect(string plaintext)
    {
        return _protector.Protect(plaintext);
    }

    public string? TryUnprotect(string protectedValue) => TryUnprotect(_protector, protectedValue);

    /// <summary>
    /// The one place that turns a Data Protection failure into null, shared
    /// with <see cref="SmtpPasswordProtector"/> so the two cannot drift.
    /// </summary>
    internal static string? TryUnprotect(IDataProtector protector, string protectedValue)
    {
        try
        {
            return protector.Unprotect(protectedValue);
        }
        catch (CryptographicException)
        {
            // Wrong keyring, wrong purpose or tampered value.
            return null;
        }
        catch (FormatException)
        {
            // Not a Data Protection payload at all (hand edited database or overlay).
            return null;
        }
    }
}
