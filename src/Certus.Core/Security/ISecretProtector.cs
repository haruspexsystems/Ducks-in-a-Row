namespace Certus.Core.Security;

/// <summary>
/// Encrypts small secrets for storage at rest and decrypts them on use.
/// Introduced for the EAB MAC secrets (RFC 8555 §7.3.4): the server must keep
/// the raw key to verify future registrations, so it cannot be hashed, only
/// encrypted. Backed by ASP.NET Data Protection in the hosts; tests use the
/// ephemeral provider so nothing touches the machine keyring or the disk.
/// </summary>
public interface ISecretProtector
{
    /// <summary>Encrypts a plaintext secret for storage.</summary>
    string Protect(string plaintext);

    /// <summary>
    /// Decrypts a stored value, or null when it cannot be decrypted (tampered
    /// value, or a keyring that does not match, for example after the data
    /// directory was restored onto a different machine). Callers must treat
    /// null as fail closed: the secret is unusable until it is regenerated.
    /// </summary>
    string? TryUnprotect(string protectedValue);
}
