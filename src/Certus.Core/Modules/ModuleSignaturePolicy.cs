using System.Security.Cryptography.X509Certificates;

namespace Certus.Core.Modules;

/// <summary>
/// Who may sign a paid module, and which roots its signing chain may end in (issue #636, CRA risk
/// R13). The core verifies every module file's Authenticode signature against this before the
/// module is loaded, so a module signed by anyone else, or not at all, never runs.
///
/// <para>The expected publisher is a constant here, like the pinned Apple attestation root, and not
/// a setting: a setting could be edited by whoever can edit the configuration, and the point of the
/// check is that only Haruspex can produce a module this service will load. The production policy
/// trusts the Windows trusted root store, so a reissued Certum certificate needs no release; a test
/// hands in its own root instead, because nothing may be installed into the machine's store to run
/// the suite.</para>
/// </summary>
public sealed class ModuleSignaturePolicy
{
    /// <summary>
    /// The publisher of every paid module: the CN and the O of the signing certificate's subject,
    /// each exactly this name. It is the same name <c>Select-SigningCertificate</c> in build.ps1
    /// signs the core with, parsed from the subject and never substring matched.
    /// </summary>
    public const string HaruspexPublisher = "Haruspex Systems B.V.";

    /// <summary>The production policy: signed by Haruspex, chaining to a root Windows trusts.</summary>
    public static ModuleSignaturePolicy Haruspex { get; } = new(HaruspexPublisher, HaruspexPublisher, trustAnchors: null);

    /// <summary>
    /// No signature check at all. Only the Development override <c>Certus:Modules:DevelopmentTrustAll</c>
    /// selects it, for the unsigned test module Certus-Commercial publishes; that override already
    /// disables the folder trust gate, so a developer box trusting its own build is the one case.
    /// </summary>
    public static ModuleSignaturePolicy Unchecked { get; } = new();

    private ModuleSignaturePolicy()
    {
        CommonName = string.Empty;
        Organisation = string.Empty;
        IsEnforced = false;
    }

    /// <summary>
    /// A policy that expects <paramref name="commonName"/> as the signer's CN and
    /// <paramref name="organisation"/> as its O, chaining to one of <paramref name="trustAnchors"/>,
    /// or to the Windows trusted root store when that is null.
    /// </summary>
    public ModuleSignaturePolicy(string commonName, string organisation, X509Certificate2Collection? trustAnchors)
    {
        ArgumentException.ThrowIfNullOrWhiteSpace(commonName);
        ArgumentException.ThrowIfNullOrWhiteSpace(organisation);
        CommonName = commonName;
        Organisation = organisation;
        TrustAnchors = trustAnchors;
        IsEnforced = true;
    }

    /// <summary>The CN the signing certificate's subject must carry, compared ordinally.</summary>
    public string CommonName { get; }

    /// <summary>The O the signing certificate's subject must carry, compared ordinally.</summary>
    public string Organisation { get; }

    /// <summary>The roots a signing chain may end in; null means the Windows trusted root store.</summary>
    public X509Certificate2Collection? TrustAnchors { get; }

    /// <summary>False only for <see cref="Unchecked"/>.</summary>
    public bool IsEnforced { get; }
}
