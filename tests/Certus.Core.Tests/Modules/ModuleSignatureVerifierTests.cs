using System.Security.Cryptography;
using System.Runtime.InteropServices;
using Certus.Core.Modules;
using Certus.Tests.Shared;

namespace Certus.Core.Tests.Modules;

/// <summary>
/// The chain, the signers and the policy the signature tests share: one test root, a publisher the
/// policy expects, another it does not, a timestamp authority, and a second root nobody trusts.
/// Keys are made once per class, because RSA key generation is the slow part.
/// </summary>
public sealed class SignatureFixture : IDisposable
{
    public const string Publisher = "Certus Test Publisher";
    public const string Organisation = "Certus Tests";

    public static readonly DateTimeOffset TimestampedAt = new(2026, 6, 1, 12, 0, 0, TimeSpan.Zero);

    public TestSigningAuthority Authority { get; } = new();
    public TestSigningAuthority OtherAuthority { get; } = new("Somebody Else's Root");

    public SigningIdentity Signer { get; }
    public SigningIdentity OtherPublisher { get; }
    public SigningIdentity Impostor { get; }
    public SigningIdentity TimeStamper { get; }
    public ModuleSignaturePolicy Policy { get; }

    public SignatureFixture()
    {
        var from = new DateTimeOffset(2025, 1, 1, 0, 0, 0, TimeSpan.Zero);
        var until = new DateTimeOffset(2028, 1, 1, 0, 0, 0, TimeSpan.Zero);
        Signer = Authority.IssueCodeSigning(Publisher, Organisation, from, until);
        OtherPublisher = Authority.IssueCodeSigning("Other Co", "Other Co", from, until);
        // The expected name on a certificate from a root the policy does not trust.
        Impostor = OtherAuthority.IssueCodeSigning(Publisher, Organisation, from, until);
        TimeStamper = Authority.IssueTimeStamping("Certus Test TSA", new DateTimeOffset(2019, 6, 1, 0, 0, 0, TimeSpan.Zero), new DateTimeOffset(2048, 1, 1, 0, 0, 0, TimeSpan.Zero));
        Policy = new ModuleSignaturePolicy(Publisher, Organisation, Authority.Anchors);
    }

    /// <summary>A stand in module assembly signed by the expected publisher, with a timestamp.</summary>
    public byte[] SignedModule(byte[]? image = null) =>
        AuthenticodeTestSigner.SignPortableExecutable(image ?? ModuleAssemblyBuilder.Module(), Signer, TimeStamper, TimestampedAt);

    /// <summary>A detached signature over <paramref name="content"/> by the expected publisher, with a timestamp.</summary>
    public byte[] SignedDetached(byte[] content) =>
        AuthenticodeTestSigner.SignDetached(content, Signer, TimeStamper, TimestampedAt);

    public void Dispose()
    {
        Signer.Dispose();
        OtherPublisher.Dispose();
        Impostor.Dispose();
        TimeStamper.Dispose();
        Authority.Dispose();
        OtherAuthority.Dispose();
    }
}

/// <summary>
/// The Authenticode check the module host runs before loading a module (issue #636): unsigned,
/// signed by somebody else, signed from an untrusted root, changed after signing and untimestamped
/// files are refused; a timestamped signature by the expected publisher is accepted, including
/// after its certificate has expired, which is the point of the timestamp.
/// </summary>
public class ModuleSignatureVerifierTests(SignatureFixture chain) : IClassFixture<SignatureFixture>, IDisposable
{
    private readonly string _root = Path.Combine(Path.GetTempPath(), $"certus-signature-{Guid.NewGuid():N}");

    public void Dispose()
    {
        try { Directory.Delete(_root, recursive: true); }
        catch (IOException) { }
        catch (UnauthorizedAccessException) { }
    }

    private string Write(string name, byte[] bytes)
    {
        Directory.CreateDirectory(_root);
        var path = Path.Combine(_root, name);
        File.WriteAllBytes(path, bytes);
        return path;
    }

    [Fact]
    public void Refuses_AnUnsignedFile()
    {
        var verdict = ModuleSignatureVerifier.VerifyPortableExecutable(Write("paid.dll", ModuleAssemblyBuilder.Module()), chain.Policy);

        verdict.IsValid.Should().BeFalse();
        verdict.FileName.Should().Be("paid.dll");
        verdict.FoundPublisher.Should().BeNull("nobody signed it");
        verdict.Reason.Should().Be("is not signed");
    }

    [Fact]
    public void Accepts_AFileSignedByTheExpectedPublisher_WithATimestamp()
    {
        var verdict = ModuleSignatureVerifier.VerifyPortableExecutable(Write("paid.dll", chain.SignedModule()), chain.Policy);

        verdict.IsValid.Should().BeTrue(verdict.Reason);
        verdict.FoundPublisher.Should().Be(SignatureFixture.Publisher);
    }

    [Fact]
    public void Refuses_AFileSignedByAnotherPublisher_NamingBoth()
    {
        var signed = AuthenticodeTestSigner.SignPortableExecutable(ModuleAssemblyBuilder.Module(), chain.OtherPublisher, chain.TimeStamper, SignatureFixture.TimestampedAt);

        var verdict = ModuleSignatureVerifier.VerifyPortableExecutable(Write("paid.dll", signed), chain.Policy);

        verdict.IsValid.Should().BeFalse();
        verdict.FoundPublisher.Should().Be("Other Co");
        verdict.Reason.Should().Be($"is signed by 'Other Co', not by '{SignatureFixture.Publisher}'");
    }

    [Fact]
    public void Refuses_TheExpectedName_OnACertificateFromAnUntrustedRoot()
    {
        // The name alone proves nothing: anyone can mint a certificate that says Haruspex. The
        // chain has to end in a root the policy trusts.
        var signed = AuthenticodeTestSigner.SignPortableExecutable(ModuleAssemblyBuilder.Module(), chain.Impostor, chain.TimeStamper, SignatureFixture.TimestampedAt);

        var verdict = ModuleSignatureVerifier.VerifyPortableExecutable(Write("paid.dll", signed), chain.Policy);

        verdict.IsValid.Should().BeFalse();
        verdict.FoundPublisher.Should().Be(SignatureFixture.Publisher);
        // Windows reports the missing root as a partial chain when the signature carries only the
        // end certificate, and as an untrusted root when the root rides along; either is refused.
        verdict.Reason.Should().Contain("is signed with a certificate that is not trusted").And.MatchRegex("PartialChain|UntrustedRoot");
    }

    [Fact]
    public void Refuses_ASignatureWithNoTimestamp()
    {
        var signed = AuthenticodeTestSigner.SignPortableExecutable(ModuleAssemblyBuilder.Module(), chain.Signer);

        var verdict = ModuleSignatureVerifier.VerifyPortableExecutable(Write("paid.dll", signed), chain.Policy);

        verdict.IsValid.Should().BeFalse();
        verdict.Reason.Should().Be("carries no timestamp");
    }

    [Fact]
    public void Refuses_AFileChangedAfterSigning()
    {
        var image = ModuleAssemblyBuilder.Module();
        var signed = chain.SignedModule(image);
        // A byte inside the sections, well before the certificate table appended at the end.
        signed[image.Length / 2] ^= 0x01;

        var verdict = ModuleSignatureVerifier.VerifyPortableExecutable(Write("paid.dll", signed), chain.Policy);

        verdict.IsValid.Should().BeFalse();
        verdict.FoundPublisher.Should().Be(SignatureFixture.Publisher, "the signature itself is intact and names its signer");
        verdict.Reason.Should().Be("does not match its signature: the file was changed after it was signed");
    }

    [Fact]
    public void Accepts_ASignatureWhoseCertificateHasSinceExpired_WhenTheTimestampFallsInsideItsValidity()
    {
        // The signing policy decision for #636: both chains are judged at the time the timestamp
        // certifies, so a module signed while the certificate was valid keeps loading after the
        // certificate expires. Without this, every installed module would stop at that date.
        using var expired = chain.Authority.IssueCodeSigning(SignatureFixture.Publisher, SignatureFixture.Organisation,
            new DateTimeOffset(2020, 1, 1, 0, 0, 0, TimeSpan.Zero), new DateTimeOffset(2021, 1, 1, 0, 0, 0, TimeSpan.Zero));
        var signed = AuthenticodeTestSigner.SignPortableExecutable(ModuleAssemblyBuilder.Module(), expired, chain.TimeStamper,
            new DateTimeOffset(2020, 6, 1, 0, 0, 0, TimeSpan.Zero));

        var verdict = ModuleSignatureVerifier.VerifyPortableExecutable(Write("paid.dll", signed), chain.Policy);

        verdict.IsValid.Should().BeTrue(verdict.Reason);
    }

    [Fact]
    public void Refuses_ASignatureTimestampedAfterItsCertificateExpired()
    {
        using var expired = chain.Authority.IssueCodeSigning(SignatureFixture.Publisher, SignatureFixture.Organisation,
            new DateTimeOffset(2020, 1, 1, 0, 0, 0, TimeSpan.Zero), new DateTimeOffset(2021, 1, 1, 0, 0, 0, TimeSpan.Zero));
        var signed = AuthenticodeTestSigner.SignPortableExecutable(ModuleAssemblyBuilder.Module(), expired, chain.TimeStamper,
            new DateTimeOffset(2022, 1, 1, 0, 0, 0, TimeSpan.Zero));

        var verdict = ModuleSignatureVerifier.VerifyPortableExecutable(Write("paid.dll", signed), chain.Policy);

        verdict.IsValid.Should().BeFalse();
        verdict.Reason.Should().Contain("is signed with a certificate that is not trusted").And.Contain("NotTimeValid");
    }

    [Fact]
    public void Refuses_ASha1FileDigest_HoweverSoundTheSignature()
    {
        // The design note's decision: SHA-1 and MD5 digests are refused whatever Windows itself
        // still accepts, because a second preimage on the file hash is the attack this check stops.
        var signed = AuthenticodeTestSigner.SignPortableExecutable(ModuleAssemblyBuilder.Module(), chain.Signer, chain.TimeStamper,
            SignatureFixture.TimestampedAt, HashAlgorithmName.SHA1);

        var verdict = ModuleSignatureVerifier.VerifyPortableExecutable(Write("paid.dll", signed), chain.Policy);

        verdict.IsValid.Should().BeFalse();
        verdict.FoundPublisher.Should().Be(SignatureFixture.Publisher);
        verdict.Reason.Should().Contain("1.3.14.3.2.26 is not accepted");
    }

    /// <summary>
    /// The installed dotnet.exe: the one real signtool output on every machine the suite runs on,
    /// found three levels above the shared framework the tests run on.
    /// </summary>
    private static string DotnetHost()
    {
        RuntimeInformation.IsOSPlatform(OSPlatform.Windows).Should().BeTrue("the module host is Windows only");
        var dotnet = Path.GetFullPath(Path.Combine(RuntimeEnvironment.GetRuntimeDirectory(), "..", "..", "..", "dotnet.exe"));
        File.Exists(dotnet).Should().BeTrue($"the runtime directory should sit three levels under the dotnet root ({dotnet})");
        return dotnet;
    }

    [Fact]
    public void Accepts_TheDotnetHost_SignedByMicrosoft_AgainstTheWindowsRootStore()
    {
        // It proves the Authenticode hash, the certificate table walk and the RFC 3161 timestamp
        // handling against a signature this code did not make, with the production trust mode (the
        // Windows root store). The subject is Microsoft's .NET signing identity, pinned here as a
        // fact about the installed runtime; a change in it is worth knowing about.
        var verdict = ModuleSignatureVerifier.VerifyPortableExecutable(DotnetHost(), new ModuleSignaturePolicy(".NET", "Microsoft Corporation", trustAnchors: null));

        verdict.IsValid.Should().BeTrue(verdict.Reason);
        verdict.FoundPublisher.Should().Be(".NET");
    }

    [Fact]
    public void Refuses_TheDotnetHost_UnderTheHaruspexPolicy_NamingBothPublishers()
    {
        var verdict = ModuleSignatureVerifier.VerifyPortableExecutable(DotnetHost(), ModuleSignaturePolicy.Haruspex);

        verdict.IsValid.Should().BeFalse();
        verdict.FoundPublisher.Should().Be(".NET");
        verdict.Reason.Should().Be($"is signed by '.NET', not by '{ModuleSignaturePolicy.HaruspexPublisher}'");
    }

    [Fact]
    public void Detached_RefusesAMissingSignatureFile()
    {
        var manifest = Write("module.json", "{}"u8.ToArray());

        var verdict = ModuleSignatureVerifier.VerifyDetached(manifest, manifest + ".p7", chain.Policy);

        verdict.IsValid.Should().BeFalse();
        verdict.FileName.Should().Be("module.json");
        verdict.Reason.Should().Be("has no signature file (module.json.p7 is missing)");
    }

    [Fact]
    public void Detached_AcceptsTheExpectedPublisher_AndRefusesAnother()
    {
        var content = "{\"id\":\"paid\"}"u8.ToArray();
        var manifest = Write("module.json", content);
        var good = Write("good.p7s", chain.SignedDetached(content));
        var other = Write("other.p7s", AuthenticodeTestSigner.SignDetached(content, chain.OtherPublisher, chain.TimeStamper, SignatureFixture.TimestampedAt));

        ModuleSignatureVerifier.VerifyDetached(manifest, good, chain.Policy).IsValid.Should().BeTrue();

        var verdict = ModuleSignatureVerifier.VerifyDetached(manifest, other, chain.Policy);
        verdict.IsValid.Should().BeFalse();
        verdict.Reason.Should().Be($"is signed by 'Other Co', not by '{SignatureFixture.Publisher}'");
    }

    [Fact]
    public void Detached_RefusesContentChangedAfterSigning()
    {
        var signature = Write("module.json.p7", chain.SignedDetached("{\"id\":\"paid\"}"u8.ToArray()));
        var manifest = Write("module.json", "{\"id\":\"paid\",\"files\":[]}"u8.ToArray());

        var verdict = ModuleSignatureVerifier.VerifyDetached(manifest, signature, chain.Policy);

        verdict.IsValid.Should().BeFalse();
        verdict.FoundPublisher.Should().Be(SignatureFixture.Publisher);
        verdict.Reason.Should().StartWith("carries a signature that does not verify");
    }

    [Fact]
    public void CheckModule_RefusesTheManifestFirst_ThenEachAssembly_AndPassesWhenAllAreSigned()
    {
        Directory.CreateDirectory(_root);
        var entry = chain.SignedModule();
        var helperImage = ModuleAssemblyBuilder.Build("Helper", [ModuleAssemblyBuilder.SystemRuntime]);
        var helper = chain.SignedModule(helperImage);
        File.WriteAllBytes(Path.Combine(_root, "paid.dll"), entry);
        File.WriteAllBytes(Path.Combine(_root, "helper.dll"), helper);
        File.WriteAllText(Path.Combine(_root, "paid.deps.json"), "{}");
        ModuleFolders.WriteManifest(_root, Path.GetFileName(_root), "paid.dll", "T", "1.0",
        [
            ("paid.dll", ModuleFolders.Sha(entry)),
            ("helper.dll", ModuleFolders.Sha(helper)),
            ("paid.deps.json", ModuleFolders.Sha("{}"u8.ToArray())),
        ]);
        var manifest = ModuleManifestReader.Read(_root);
        manifest.Manifest.Should().NotBeNull(manifest.Error);

        // No manifest signature yet: the manifest is the first refusal, before any assembly.
        var unsignedManifest = ModuleSignatureVerifier.CheckModule(_root, manifest.Manifest!, chain.Policy);
        unsignedManifest.Should().NotBeNull();
        unsignedManifest!.FileName.Should().Be("module.json");

        File.WriteAllBytes(Path.Combine(_root, ModuleSignatureVerifier.ManifestSignatureFileName),
            chain.SignedDetached(File.ReadAllBytes(Path.Combine(_root, "module.json"))));

        // Everything signed: no refusal. The deps.json is not a PE file and is covered by the
        // signed manifest's hash alone.
        ModuleSignatureVerifier.CheckModule(_root, manifest.Manifest!, chain.Policy).Should().BeNull();

        // Swap the helper for its unsigned image (the manifest reader would catch the hash first
        // on a real load; this isolates the signature walk): the entry passes, the helper is named.
        File.WriteAllBytes(Path.Combine(_root, "helper.dll"), helperImage);
        var unsignedHelper = ModuleSignatureVerifier.CheckModule(_root, manifest.Manifest!, chain.Policy);
        unsignedHelper.Should().NotBeNull();
        unsignedHelper!.FileName.Should().Be("helper.dll");
        unsignedHelper.Reason.Should().Be("is not signed");
    }

    [Fact]
    public void CheckModule_ChecksNothing_UnderTheUncheckedPolicy()
    {
        Directory.CreateDirectory(_root);
        var image = ModuleAssemblyBuilder.Module();
        File.WriteAllBytes(Path.Combine(_root, "paid.dll"), image);
        ModuleFolders.WriteManifest(_root, Path.GetFileName(_root), "paid.dll", "T", "1.0", [("paid.dll", ModuleFolders.Sha(image))]);
        var manifest = ModuleManifestReader.Read(_root);

        ModuleSignatureVerifier.CheckModule(_root, manifest.Manifest!, ModuleSignaturePolicy.Unchecked).Should().BeNull();
        ModuleSignaturePolicy.Unchecked.IsEnforced.Should().BeFalse();
        ModuleSignaturePolicy.Haruspex.IsEnforced.Should().BeTrue();
        ModuleSignaturePolicy.Haruspex.TrustAnchors.Should().BeNull("production trusts the Windows root store");
    }
}
