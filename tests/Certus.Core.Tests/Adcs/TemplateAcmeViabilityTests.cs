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
    public void KeyAlgorithm_PrefersTheV3Attribute()
    {
        Build(asymmetricAlgorithm: "RSA").KeyAlgorithm.Should().Be("RSA");
        Build(asymmetricAlgorithm: "ECDSA_P256", defaultCsps: new[] { "1,Microsoft RSA SChannel Cryptographic Provider" })
            .KeyAlgorithm.Should().Be("ECDSA_P256");
    }

    [Fact]
    public void KeyAlgorithm_InfersRsaFromLegacyCsps()
    {
        // v1/v2 templates carry only pKIDefaultCSPs. Every legacy provider is
        // an RSA provider except the DSS ones.
        Build(defaultCsps: new[]
        {
            "1,Microsoft RSA SChannel Cryptographic Provider",
            "2,Microsoft DH SChannel Cryptographic Provider",
        }).KeyAlgorithm.Should().Be("RSA");

        Build(defaultCsps: new[] { "1,Microsoft Base DSS Cryptographic Provider" })
            .KeyAlgorithm.Should().Be("DSA");
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

    private static TemplateAcmeViability Build(
        int? enrollmentFlags = null,
        int? raSignatureCount = null,
        int? certificateNameFlags = null,
        string? asymmetricAlgorithm = null,
        IReadOnlyList<string>? defaultCsps = null,
        int? minimalKeySize = null)
    {
        return TemplateAcmeViability.FromAdAttributes(
            enrollmentFlags,
            raSignatureCount,
            certificateNameFlags,
            asymmetricAlgorithm,
            defaultCsps ?? Array.Empty<string>(),
            minimalKeySize);
    }
}
