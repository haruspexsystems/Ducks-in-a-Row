using Microsoft.AspNetCore.DataProtection;

namespace Certus.Core.Security;

/// <summary>
/// <see cref="ISmtpSecretProtector"/> over ASP.NET Data Protection, on the
/// same keyring as <see cref="DataProtectionSecretProtector"/> and under its
/// own purpose (issue #635). Until that issue the SMTP password was protected
/// under the EAB purpose, so <see cref="TryUnprotect"/> still accepts a blob
/// written that way, and <see cref="Rewrite"/> is how the save path moves it.
/// </summary>
public sealed class SmtpPasswordProtector : ISmtpSecretProtector
{
    /// <summary>The purpose every SMTP password is written under from issue #635 on.</summary>
    public const string Purpose = "Certus.Smtp.v1";

    private readonly IDataProtector _current;
    private readonly IDataProtector _legacy;

    public SmtpPasswordProtector(IDataProtectionProvider provider)
    {
        _current = provider.CreateProtector(Purpose);
        _legacy = provider.CreateProtector(DataProtectionSecretProtector.Purpose);
    }

    public string Protect(string plaintext) => _current.Protect(plaintext);

    public string? TryUnprotect(string protectedValue) =>
        DataProtectionSecretProtector.TryUnprotect(_current, protectedValue)
        ?? DataProtectionSecretProtector.TryUnprotect(_legacy, protectedValue);

    public string Rewrite(string protectedValue)
    {
        if (DataProtectionSecretProtector.TryUnprotect(_current, protectedValue) is not null)
            return protectedValue;

        // Only a blob the legacy purpose reads is rewritten. One neither reads
        // is left exactly as it was: it is the keyring that cannot decrypt it
        // (a data folder restored elsewhere), and replacing it would turn the
        // notifier's clear "could not be read on this machine" refusal into a
        // password that silently changed.
        return DataProtectionSecretProtector.TryUnprotect(_legacy, protectedValue) is { } plaintext
            ? _current.Protect(plaintext)
            : protectedValue;
    }
}
