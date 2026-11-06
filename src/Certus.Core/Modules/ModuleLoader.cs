using System.Reflection;

namespace Certus.Core.Modules;

/// <summary>What discovery found in the modules folder.</summary>
public enum ModuleDiscoveryOutcome
{
    /// <summary>No modules folder, or an empty one.</summary>
    None,

    /// <summary>More than one module folder; none is loaded, because two verifiers could disagree.</summary>
    Multiple,

    /// <summary>Exactly one module folder.</summary>
    One,
}

/// <summary>The result of looking in the modules folder (licence design section 6.2, step 1).</summary>
public sealed record ModuleDiscovery(ModuleDiscoveryOutcome Outcome, string? FolderPath, string? Reason);

/// <summary>How a module folder fared against the static checks of the load path.</summary>
public enum ModuleValidationOutcome
{
    /// <summary>Every check passed; the module may be loaded.</summary>
    Ready,

    /// <summary>The manifest or the metadata check refused it for a reason other than the ones below.</summary>
    Failed,

    /// <summary>The folder trust gate refused the folder, so nothing in it was read.</summary>
    Refused,

    /// <summary>The module was built against a contract version this core cannot satisfy.</summary>
    Incompatible,

    /// <summary>
    /// A file's signature could not be verified: unsigned, signed by another publisher, changed
    /// after signing, or not chaining to a trusted root (issue #636). The manifest was read and
    /// passed, so the module's id and version are known, and <see cref="ModuleValidation.Signature"/>
    /// names the file. Added at the end so the earlier values keep their numbers.
    /// </summary>
    SignatureRefused,
}

/// <summary>
/// The result of validating a module folder short of loading it: the gate, the manifest, the
/// signature check and the metadata reference check all passed, or a reason the module was not
/// loaded. <see cref="Manifest"/> is set only when the module is ready, so nothing can activate a
/// module that failed a check.
/// </summary>
public sealed record ModuleValidation(ModuleValidationOutcome Outcome, string? Reason, ModuleManifest? Manifest, string? EntryAssemblyPath)
{
    public bool IsReady => Outcome == ModuleValidationOutcome.Ready;

    /// <summary>The manifest's module id, for a module whose manifest was read and passed but which was refused after that.</summary>
    public string? ModuleId { get; init; }

    /// <summary>The manifest's module version, under the same condition.</summary>
    public string? ModuleVersion { get; init; }

    /// <summary>The contract version the module's entry assembly references, for an incompatible module only.</summary>
    public Version? ModuleContract { get; init; }

    /// <summary>The file whose signature was refused, and who signed it, for <see cref="ModuleValidationOutcome.SignatureRefused"/> only.</summary>
    public ModuleSignatureVerdict? Signature { get; init; }
}

/// <summary>
/// The static steps of the load path that open no module and run no module code (licence design
/// section 6.2, steps 1 to 4 and 6): discovery, the folder trust gate, the manifest, the signature
/// check (issue #636), and the metadata reference allow list, then the assembly load. Creating the
/// entry type and calling into it are the host's, on the module's own thread.
/// </summary>
public static class ModuleLoader
{
    /// <summary>Looks for exactly one module subfolder in <paramref name="modulesRoot"/>.</summary>
    public static ModuleDiscovery Discover(string modulesRoot)
    {
        ArgumentException.ThrowIfNullOrWhiteSpace(modulesRoot);

        if (!Directory.Exists(modulesRoot))
            return new ModuleDiscovery(ModuleDiscoveryOutcome.None, null, "no modules folder is present");

        var folders = Directory.EnumerateDirectories(modulesRoot).ToList();
        if (folders.Count == 0)
            return new ModuleDiscovery(ModuleDiscoveryOutcome.None, null, "no module is installed");

        if (folders.Count > 1)
            return new ModuleDiscovery(ModuleDiscoveryOutcome.Multiple, null,
                $"more than one module folder is present ({folders.Count}); none is loaded");

        return new ModuleDiscovery(ModuleDiscoveryOutcome.One, System.IO.Path.GetFullPath(folders[0]), null);
    }

    /// <summary>
    /// Runs the folder trust gate (unless <paramref name="trustAll"/>, a Development only override),
    /// the manifest check, the signature check under <paramref name="signatures"/>, and the metadata
    /// reference check over <paramref name="moduleFolder"/>.
    /// </summary>
    public static ModuleValidation Validate(
        string installBase, string moduleFolder, bool trustAll, Version coreContractVersion, ModuleSignaturePolicy signatures)
    {
        ArgumentException.ThrowIfNullOrWhiteSpace(installBase);
        ArgumentException.ThrowIfNullOrWhiteSpace(moduleFolder);
        ArgumentNullException.ThrowIfNull(coreContractVersion);
        ArgumentNullException.ThrowIfNull(signatures);

        if (!trustAll)
        {
            // The gate walks the chain from the install folder down to the module, so a module
            // folder outside it has no chain to walk and is refused here. Only a Development path
            // can put one there; asking the gate anyway made it throw, and the host reported that as
            // "the module host failed" rather than as the refusal it is.
            //
            // Both refusals are Refused rather than Failed, so the card can tell an administrator to
            // repair the installation (design section 13.3). The manifest is deliberately not read on
            // this path: the gate exists so that nothing in an untrusted folder is opened.
            if (!FolderTrust.IsAtOrUnder(System.IO.Path.GetFullPath(installBase), System.IO.Path.GetFullPath(moduleFolder)))
                return Refuse(ModuleValidationOutcome.Refused, "the module folder is not trusted: it is not inside the install folder");

            var trust = FolderTrust.CheckModule(installBase, moduleFolder);
            if (!trust.IsTrusted)
                return Refuse(ModuleValidationOutcome.Refused, $"the module folder is not trusted: {trust.Reason}");
        }

        var manifest = ModuleManifestReader.Read(moduleFolder);
        if (!manifest.IsValid)
            return Refuse(ModuleValidationOutcome.Failed, manifest.Error);

        // The signatures are checked before any assembly's metadata is parsed, so the only bytes
        // read from an unverified file are the ones the signature check itself needs (#636). The
        // manifest's own detached signature comes first: it is what ties the set of files
        // together, so an unsigned manifest is refused before any file it lists is looked at.
        if (ModuleSignatureVerifier.CheckModule(moduleFolder, manifest.Manifest!, signatures) is { } signature)
        {
            return Refuse(ModuleValidationOutcome.SignatureRefused,
                $"the paid module's signature could not be verified: '{signature.FileName}' {signature.Reason}") with
            {
                ModuleId = manifest.Manifest!.Id,
                ModuleVersion = manifest.Manifest.Version,
                Signature = signature,
            };
        }

        // Every listed assembly is held to the reference allow list, not only the entry: a helper's
        // reference would otherwise reach the default context through the load context just as the
        // entry's would. The listed files are also what defines the module's own assemblies.
        var listed = manifest.Manifest!.Files
            .Select(file => System.IO.Path.GetFullPath(System.IO.Path.Combine(moduleFolder, file.Path)));
        var metadata = ModuleMetadataReader.CheckModule(manifest.EntryAssemblyPath!, listed, coreContractVersion);
        if (metadata.IsIncompatible)
        {
            // The manifest passed, so its id and version are worth showing: the card's Incompatible
            // text names the module's version beside the two contract numbers.
            return Refuse(ModuleValidationOutcome.Incompatible, metadata.Error) with
            {
                ModuleId = manifest.Manifest!.Id,
                ModuleVersion = manifest.Manifest.Version,
                ModuleContract = metadata.ContractVersion,
            };
        }

        if (!metadata.IsOk)
            return Refuse(ModuleValidationOutcome.Failed, metadata.Error);

        return new ModuleValidation(ModuleValidationOutcome.Ready, null, manifest.Manifest, manifest.EntryAssemblyPath);
    }

    private static ModuleValidation Refuse(ModuleValidationOutcome outcome, string? reason) =>
        new(outcome, reason, null, null);

    /// <summary>
    /// Creates the module's load context and loads its entry assembly from the signed file. The
    /// caller owns the returned context and keeps it alive for the life of the process.
    /// </summary>
    internal static (ModuleLoadContext Context, Assembly EntryAssembly) Load(ModuleManifest manifest, string entryAssemblyPath)
    {
        var context = new ModuleLoadContext($"module:{manifest.Id}", entryAssemblyPath);
        var assembly = context.LoadFromAssemblyPath(entryAssemblyPath);
        return (context, assembly);
    }
}
