using System.Text;

namespace Certus.Adcs;

/// <summary>
/// RFC 4515 escaping for one value embedded in an LDAP filter, so a value can
/// never terminate or extend the filter expression.
///
/// Lives on its own rather than inside <see cref="AdPrincipalLookup"/> because
/// the service rights reader needs it too, and that reader is also compiled into
/// tools/AdcsQiProbe. Keep it to the base class library and C# 12.
/// </summary>
internal static class LdapFilterValue
{
    /// <summary>Escapes <paramref name="value"/> for use inside a filter.</summary>
    internal static string Escape(string value)
    {
        var sb = new StringBuilder(value.Length);
        foreach (var ch in value)
        {
            switch (ch)
            {
                case '\\': sb.Append(@"\5c"); break;
                case '*': sb.Append(@"\2a"); break;
                case '(': sb.Append(@"\28"); break;
                case ')': sb.Append(@"\29"); break;
                case '\0': sb.Append(@"\00"); break;
                default: sb.Append(ch); break;
            }
        }
        return sb.ToString();
    }
}
