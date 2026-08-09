using System.Security.Cryptography;
using Microsoft.AspNetCore.DataProtection;

namespace Certus.Core.Security;

/// <summary>
/// <see cref="ISecretProtector"/> over ASP.NET Data Protection. The hosts
/// persist the keyring to a "keys" folder next to the database and protect it
/// with DPAPI on Windows, so backups of the data directory carry the keyring
/// but a restore onto a different machine cannot decrypt it. That failure
/// surfaces here as <see cref="TryUnprotect"/> returning null; the recovery is
/// regenerating the credential secret (the key id and its configuration are
/// plaintext columns and survive).
/// </summary>
public sealed class DataProtectionSecretProtector : ISecretProtector
{
    /// <summary>
    /// The protector purpose string. Versioned so a future format change can
    /// introduce a new purpose without breaking values written under this one.
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

    public string? TryUnprotect(string protectedValue)
    {
        try
        {
            return _protector.Unprotect(protectedValue);
        }
        catch (CryptographicException)
        {
            // Wrong keyring or tampered value.
            return null;
        }
        catch (FormatException)
        {
            // Not a Data Protection payload at all (hand edited database).
            return null;
        }
    }
}
