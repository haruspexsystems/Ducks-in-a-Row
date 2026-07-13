namespace Certus.Core.Adcs;

/// <summary>
/// Creates an <see cref="IAdcsClient"/> for an explicit CA connection string.
/// The setup wizard uses this to probe a candidate CA before anything is
/// persisted: the DI bound singleton client reflects the configuration the
/// service started with, which during setup is the unconfigured client (or the
/// mock), so probing through it would test the wrong thing.
///
/// Callers own the returned instance and must dispose it when it implements
/// <see cref="IDisposable"/>.
/// </summary>
public interface IAdcsClientFactory
{
    IAdcsClient Create(string caConnectionString);
}

/// <summary>
/// Factory returning the mock client regardless of the connection string.
/// Used by the development host and whenever Certus:UseMockCa is enabled.
/// </summary>
public sealed class MockAdcsClientFactory : IAdcsClientFactory
{
    public IAdcsClient Create(string caConnectionString) => new MockAdcsClient();
}
