using Certus.Core.Adcs;

namespace Certus.Core.Tests.Adcs;

/// <summary>
/// Tests for the CertificateQuery record's defaults, which the paging and filtering paths
/// rely on — notably the default page size of 50.
/// </summary>
public class CertificateQueryTests
{
    [Fact]
    public void CertificateQuery_DefaultValues_AreCorrect()
    {
        var query = new CertificateQuery();

        query.TemplateName.Should().BeNull();
        query.SubjectContains.Should().BeNull();
        query.Status.Should().BeNull();
        query.ExpiringBefore.Should().BeNull();
        query.Skip.Should().Be(0);
        query.Take.Should().Be(50);
    }
}
