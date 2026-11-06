namespace Certus.Service;

/// <summary>
/// Names this assembly for <c>WebApplicationFactory&lt;ServiceHostEntryPoint&gt;</c>, which
/// boots the real service host in tests (tests/Certus.Service.Tests). The factory needs a
/// type from the assembly whose entry point it should run, and <c>Program</c> cannot be
/// that type: this assembly and Certus.Web each carry a public generated <c>Program</c>, so
/// a project that references both cannot name either one (CS0433). Nothing creates an
/// instance.
/// </summary>
public sealed class ServiceHostEntryPoint
{
    private ServiceHostEntryPoint()
    {
    }
}
