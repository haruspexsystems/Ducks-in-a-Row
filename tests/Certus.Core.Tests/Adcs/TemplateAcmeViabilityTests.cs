using Certus.Core.Adcs;

namespace Certus.Core.Tests.Adcs;

/// <summary>
/// Interpretation of the raw AD template attributes behind the wizard's ACME
/// readiness checklist. Every member must stay null (could not verify) when
/// its attribute was absent — a missing attribute is not a passing check.
/// </summary>
public class TemplateAcmeViabilityTests
{
    [Fact]
    public void ManagerApproval_ReadsThePendAllRequestsBit()
    {
        // CT_FLAG_PEND_ALL_REQUESTS is 0x2 in msPKI-Enrollment-Flag. The
        // default WebServer template ships 0x0; approval requiring templates
        // carry the bit among others (e.g. 0x2 | 0x20 = 0x22).
        Build(enrollmentFlags: 0x0).RequiresManagerApproval.Should().BeFalse();
        Build(enrollmentFlags: 0x2).RequiresManagerApproval.Should().BeTrue();
        Build(enrollmentFlags: 0x22).RequiresManagerApproval.Should().BeTrue();
        Build(enrollmentFlags: null).RequiresManagerApproval.Should().BeNull();
    }

    [Fact]
    public void RaSignatures_AnyPositiveCountRequiresThem()
    {
        Build(raSignatureCount: 0).RequiresRaSignatures.Should().BeFalse();
        Build(raSignatureCount: 1).RequiresRaSignatures.Should().BeTrue();
        Build(raSignatureCount: null).RequiresRaSignatures.Should().BeNull();
    }

    [Fact]
    public void SubjectSource_ReadsTheEnrolleeSuppliesSubjectBit()
    {
        // CT_FLAG_ENROLLEE_SUPPLIES_SUBJECT is 0x1 in
        // msPKI-Certificate-Name-Flag. AD built subjects (the Machine
        // template shape) do not carry it.
        Build(certificateNameFlags: 0x1).SubjectSuppliedInRequest.Should().BeTrue();
        Build(certificateNameFlags: 0x1 | 0x10000).SubjectSuppliedInRequest.Should().BeTrue();
        Build(certificateNameFlags: 0x40000000).SubjectSuppliedInRequest.Should().BeFalse();
        Build(certificateNameFlags: null).SubjectSuppliedInRequest.Should().BeNull();
    }

    [Fact]
    public void KeyAlgorithm_ReadsTheTriplesOnAVersion3Template()
    {
        Build(schemaVersion: 3, raApplicationPolicies: [Triples("RSA")])
            .KeyAlgorithm.Should().Be("RSA");

        // The template QA provisioned for issue #213. Its CSP list is an RSA
        // provider, so the legacy inference would answer RSA: the triple has
        // to win outright, not merely be preferred.
        Build(
            schemaVersion: 3,
            raApplicationPolicies: [Triples("ECDSA_P256")],
            defaultCsps: ["1,Microsoft Software Key Storage Provider"])
            .KeyAlgorithm.Should().Be("ECDSA_P256");
    }

    [Fact]
    public void KeyAlgorithm_ReadsTheTriplesOnAVersion4CngTemplate()
    {
        // [MS-CRTD] 2.23.2: a version 4 template carries the triples unless
        // CT_FLAG_USE_LEGACY_PROVIDER is set. Version 4 is what duplicating a
        // template with "Server 2012 R2 or later" compatibility produces, so
        // reading only version 3 would leave the common modern case broken.
        Build(schemaVersion: 4, privateKeyFlags: 0x10, raApplicationPolicies: [Triples("ECDSA_P384")])
            .KeyAlgorithm.Should().Be("ECDSA_P384");
    }

    [Fact]
    public void KeyAlgorithm_AVersion4LegacyProviderTemplateUsesTheCspInference()
    {
        // [MS-CRTD] 2.23.1: with CT_FLAG_USE_LEGACY_PROVIDER (0x100) set, the
        // attribute holds RA application policy OIDs and no algorithm at all,
        // so the CSP names are the only signal.
        Build(
            schemaVersion: 4,
            privateKeyFlags: 0x110,
            raApplicationPolicies: ["1.3.6.1.4.1.311.10.3.8"],
            defaultCsps: ["1,Microsoft RSA SChannel Cryptographic Provider"])
            .KeyAlgorithm.Should().Be("RSA");
    }

    [Fact]
    public void KeyAlgorithm_AVersion3TemplateWithNoReadableAlgorithmStaysUnknown()
    {
        // The regression issue #213 is about. This template's CSP list is a
        // Key Storage Provider, which contains no "DSS", so the legacy
        // inference would confidently answer "RSA" for a template that may
        // well be elliptic curve. It must answer null instead: an honest
        // "could not determine" is what the wizard and the enroller handle.
        Build(
            schemaVersion: 3,
            raApplicationPolicies: ["1.3.6.1.4.1.311.10.3.8"],
            defaultCsps: ["1,Microsoft Software Key Storage Provider"])
            .KeyAlgorithm.Should().BeNull();

        Build(schemaVersion: 3, defaultCsps: ["1,Microsoft Software Key Storage Provider"])
            .KeyAlgorithm.Should().BeNull();
    }

    [Fact]
    public void KeyAlgorithm_InfersRsaFromLegacyCsps()
    {
        // v1/v2 templates carry only pKIDefaultCSPs. Every legacy provider is
        // an RSA provider except the DSS ones, and none of them is elliptic
        // curve, so the inference is sound here in a way it is not above.
        Build(schemaVersion: 2, defaultCsps:
        [
            "1,Microsoft RSA SChannel Cryptographic Provider",
            "2,Microsoft DH SChannel Cryptographic Provider",
        ]).KeyAlgorithm.Should().Be("RSA");

        Build(schemaVersion: 2, defaultCsps: ["1,Microsoft Base DSS Cryptographic Provider"])
            .KeyAlgorithm.Should().Be("DSA");

        // A version 1 template carries no msPKI- attribute at all, so an
        // absent schema version is the normal shape of one rather than a
        // failed read, and the legacy inference is right for it.
        Build(defaultCsps: ["1,Microsoft RSA SChannel Cryptographic Provider"])
            .KeyAlgorithm.Should().Be("RSA");
    }

    [Fact]
    public void KeyAlgorithm_UnreadableAttributesStayUnknown()
    {
        Build().KeyAlgorithm.Should().BeNull();
    }

    [Fact]
    public void MinimalKeySize_PassesThrough()
    {
        Build(minimalKeySize: 2048).MinimalKeySize.Should().Be(2048);
        Build(minimalKeySize: null).MinimalKeySize.Should().BeNull();
    }

    /// <summary>
    /// An msPKI-RA-Application-Policies value in the [MS-CRTD] 2.23.2 shape,
    /// carrying the given algorithm. The separator is U+0060.
    /// </summary>
    private static string Triples(string algorithm) =>
        $"msPKI-Asymmetric-Algorithm`PZPWSTR`{algorithm}`msPKI-Hash-Algorithm`PZPWSTR`SHA256`";

    private static TemplateAcmeViability Build(
        int? enrollmentFlags = null,
        int? raSignatureCount = null,
        int? certificateNameFlags = null,
        int? schemaVersion = null,
        int? privateKeyFlags = null,
        IReadOnlyList<string>? raApplicationPolicies = null,
        IReadOnlyList<string>? defaultCsps = null,
        int? minimalKeySize = null)
    {
        return TemplateAcmeViability.FromAdAttributes(
            enrollmentFlags,
            raSignatureCount,
            certificateNameFlags,
            schemaVersion,
            privateKeyFlags,
            raApplicationPolicies ?? Array.Empty<string>(),
            defaultCsps ?? Array.Empty<string>(),
            minimalKeySize);
    }
}
