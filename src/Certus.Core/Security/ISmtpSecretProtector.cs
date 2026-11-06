namespace Certus.Core.Security;

/// <summary>
/// The protector for the dashboard saved SMTP password (issue #635). The same
/// contract as <see cref="ISecretProtector"/>, under its own Data Protection
/// purpose, so the SMTP blob and an EAB secret are not interchangeable
/// ciphertexts: a blob lifted from the overlay cannot be presented where an
/// EAB secret is expected, nor the other way round.
/// </summary>
public interface ISmtpSecretProtector : ISecretProtector
{
    /// <summary>
    /// A blob written under the purpose every SMTP password shared with the
    /// EAB secrets before issue #635, re-protected under the SMTP purpose, or
    /// <paramref name="protectedValue"/> itself when it is already current or
    /// cannot be read on this machine. The save path calls this on a blob it
    /// carries forward, so an old row is rewritten the next time anything on
    /// the alerts card is saved and the legacy read path can eventually go.
    /// </summary>
    string Rewrite(string protectedValue);
}
