namespace Certus.Core.Adcs;

/// <summary>
/// Reads the CNG settings ADCS packs into the <c>msPKI-RA-Application-Policies</c>
/// attribute of a certificate template.
/// </summary>
/// <remarks>
/// <para>
/// There is no <c>msPKI-Asymmetric-Algorithm</c> attribute in the Active
/// Directory schema. The name is a <em>property inside</em> this attribute's
/// value, and reading it as an attribute is what made every ECDSA template
/// report RSA (issue #213).
/// </para>
/// <para>
/// [MS-CRTD] gives the attribute two syntaxes and picks between them on more
/// than the schema version alone:
/// </para>
/// <list type="table">
///   <item>
///     <term>Section 2.23.2, triples</term>
///     <description>
///     Template version 3, or version 4 <em>without</em>
///     <c>CT_FLAG_USE_LEGACY_PROVIDER</c> set in <c>msPKI-Private-Key-Flag</c>.
///     The value is <c>Name`Type`Value`</c> repeated, separated by a grave
///     accent (U+0060), where Type is <c>PZPWSTR</c> or <c>DWORD</c>.
///     </description>
///   </item>
///   <item>
///     <term>Section 2.23.1, OID list</term>
///     <description>
///     Template version 1 or 2, or version 4 <em>with</em> that flag. The value
///     is a multistring of registration authority application policy OIDs and
///     carries no algorithm at all.
///     </description>
///   </item>
/// </list>
/// <para>
/// Version 4 is what duplicating a template with "Server 2012 R2 or later"
/// compatibility produces, so a version 3 only reading would still misreport a
/// large share of templates on a modern CA.
/// </para>
/// <para>
/// This lives in Certus.Core rather than beside the LDAP read in Certus.Adcs so
/// that it can be unit tested, the same split the CLAUDE.md notes describe for
/// <c>AdPrincipalLookup</c>: the pure parts are tested, the directory bind is
/// verified against a live lab.
/// </para>
/// </remarks>
public static class RaApplicationPolicies
{
    /// <summary>
    /// The triple separator, [MS-CRTD] 2.23.2. U+0060 GRAVE ACCENT.
    /// </summary>
    private const char Delimiter = '`';

    /// <summary>
    /// CT_FLAG_USE_LEGACY_PROVIDER in <c>msPKI-Private-Key-Flag</c>,
    /// [MS-CRTD] 2.28. On a version 4 template this is what sends the
    /// attribute back to the OID list syntax.
    /// </summary>
    private const int UseLegacyProviderFlag = 0x100;

    /// <summary>The property name holding the key algorithm.</summary>
    private const string AsymmetricAlgorithmProperty = "msPKI-Asymmetric-Algorithm";

    /// <summary>
    /// Whether this template's <c>msPKI-RA-Application-Policies</c> holds the
    /// CNG triples rather than a list of OIDs.
    /// </summary>
    /// <param name="schemaVersion">
    /// <c>msPKI-Template-Schema-Version</c>. Null means the attribute is
    /// absent, which is the normal shape of a version 1 template: the whole
    /// <c>msPKI-</c> attribute set postdates that schema. Version 1 templates
    /// never carry triples, so a null reads as false.
    /// </param>
    /// <param name="privateKeyFlags"><c>msPKI-Private-Key-Flag</c>, null when unreadable.</param>
    public static bool UsesCngTripleSyntax(int? schemaVersion, int? privateKeyFlags)
    {
        if (schemaVersion is not { } version || version <= 2)
            return false;

        if (version == 3)
            return true;

        // Version 4 and anything later ADCS grows: the legacy provider flag
        // decides. An unreadable flag is treated as clear, which is the common
        // case and the one that carries the triples.
        return privateKeyFlags is not { } flags || (flags & UseLegacyProviderFlag) == 0;
    }

    /// <summary>
    /// Pull the key algorithm out of the raw attribute values.
    /// </summary>
    /// <param name="values">
    /// Every value of <c>msPKI-RA-Application-Policies</c>. The attribute is
    /// multi valued under the OID list syntax, so this takes the whole list
    /// and reads the first value that parses.
    /// </param>
    /// <param name="algorithm">The algorithm name, verbatim and trimmed.</param>
    /// <returns>
    /// False when no value carries the property: an OID list, a malformed
    /// string, or a triple set that simply does not configure an algorithm.
    /// Callers must report that as unknown rather than substituting a guess,
    /// which is the mistake issue #213 was filed about.
    /// </returns>
    public static bool TryGetAsymmetricAlgorithm(
        IReadOnlyList<string>? values,
        out string? algorithm)
    {
        algorithm = null;
        if (values is null)
            return false;

        foreach (var value in values)
        {
            if (!TryReadFromSingleValue(value, out var found))
                continue;

            algorithm = found;
            return true;
        }

        return false;
    }

    private static bool TryReadFromSingleValue(string? value, out string? algorithm)
    {
        algorithm = null;
        if (string.IsNullOrWhiteSpace(value) || !value.Contains(Delimiter, StringComparison.Ordinal))
            return false;

        var tokens = value.Split(Delimiter);

        // Each triple is written "Name`Type`Value`", trailing delimiter and
        // all, so a well formed value splits into one empty tail token. Drop
        // it before the length check, and tolerate its absence.
        var length = tokens.Length;
        if (length > 0 && tokens[length - 1].Length == 0)
            length--;

        // A token count that does not divide into threes means the value is
        // not the syntax we think it is. Refuse the whole value rather than
        // read a misaligned triple, which could pick up a Type token as a
        // Value.
        if (length == 0 || length % 3 != 0)
            return false;

        for (var i = 0; i < length; i += 3)
        {
            if (!tokens[i].Equals(AsymmetricAlgorithmProperty, StringComparison.OrdinalIgnoreCase))
                continue;

            var candidate = tokens[i + 2].Trim();
            if (candidate.Length == 0)
                return false;

            algorithm = candidate;
            return true;
        }

        return false;
    }
}
