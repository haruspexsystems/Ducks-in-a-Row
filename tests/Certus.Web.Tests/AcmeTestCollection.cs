namespace Certus.Web.Tests;

/// <summary>
/// Defines a shared test collection for all ACME integration tests.
/// Tests in this collection share a single CertusWebApplicationFactory instance
/// and run sequentially to avoid WebApplicationFactory concurrency issues.
/// </summary>
[CollectionDefinition("ACME Integration")]
public class AcmeTestCollection : ICollectionFixture<CertusWebApplicationFactory>
{
    // This class has no code; it only serves as a collection definition anchor.
}
