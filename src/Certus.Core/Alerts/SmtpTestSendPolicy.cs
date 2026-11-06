namespace Certus.Core.Alerts;

/// <summary>
/// Where a stored SMTP password may be sent by a test send (issue #635, CRA
/// R09). A candidate test send that omits the password falls back to the
/// stored one, which is right for proving the saved relay still answers and
/// wrong for anything else: an administrator, or a relayed administrator
/// session, could otherwise point the form at a host of their choosing with
/// TLS off and collect the password. So the stored password goes only to the
/// relay it was saved for, on the same port and with the same transport
/// security; a test aimed anywhere else has to carry its own password.
/// </summary>
public static class SmtpTestSendPolicy
{
    /// <summary>What the dashboard shows when the test is refused.</summary>
    public const string Refusal =
        "The stored SMTP password is only ever sent to the relay it was saved for. " +
        "To test a different relay host, port or TLS mode, type the password for it.";

    /// <summary>
    /// The refusal text, or null when the test may proceed. The test may
    /// proceed when it carries its own password, when there is no stored
    /// password to protect, or when it is aimed at the saved relay on the
    /// saved port with the saved TLS mode.
    /// </summary>
    /// <param name="candidate">The values the test would connect with.</param>
    /// <param name="passwordTyped">Whether the form supplied the password itself.</param>
    /// <param name="storedPasswordExists">Whether a saved or configured password would be used.</param>
    /// <param name="saved">The SMTP configuration the password was saved for, or null when none is saved.</param>
    public static string? Refuse(
        SmtpOptions candidate, bool passwordTyped, bool storedPasswordExists, SmtpOptions? saved)
    {
        ArgumentNullException.ThrowIfNull(candidate);

        if (passwordTyped || !storedPasswordExists)
            return null;

        if (saved is null || !SameRelay(candidate, saved))
            return Refusal;

        return null;
    }

    /// <summary>
    /// Host, port and the effective TLS mode. The effective mode, because an
    /// install configured before the explicit mode existed has none saved and
    /// derives one from UseSsl and the port; the comparison has to answer for
    /// what the transport would actually do.
    /// </summary>
    private static bool SameRelay(SmtpOptions candidate, SmtpOptions saved) =>
        string.Equals(candidate.Host?.Trim(), saved.Host?.Trim(), StringComparison.OrdinalIgnoreCase)
        && candidate.Port == saved.Port
        && EffectiveTlsMode(candidate) == EffectiveTlsMode(saved);

    private static SmtpTlsMode EffectiveTlsMode(SmtpOptions smtp) =>
        smtp.TlsMode ?? SmtpTlsModes.Derive(smtp.UseSsl, smtp.Port);
}
