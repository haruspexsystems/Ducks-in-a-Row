using Certus.Core.Adcs;
using Microsoft.Extensions.Logging;

namespace Certus.Adcs;

/// <summary>
/// Creates real COM interop clients for explicit CA connection strings. Used
/// by the setup wizard to probe a candidate CA through the exact dispatch path
/// production traffic uses (per the project's COM history, nothing else — not
/// certutil, not the mock — is a trustworthy witness for "can we talk to this
/// CA").
/// </summary>
public sealed class AdcsClientFactory : IAdcsClientFactory
{
    private readonly ILoggerFactory _loggerFactory;

    public AdcsClientFactory(ILoggerFactory loggerFactory)
    {
        _loggerFactory = loggerFactory;
    }

    public IAdcsClient Create(string caConnectionString)
        => new AdcsClient(caConnectionString, _loggerFactory.CreateLogger<AdcsClient>());
}
