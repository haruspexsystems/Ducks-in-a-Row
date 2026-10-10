using System.Runtime.InteropServices;
using Certus.Adcs.ComInterop;
using Certus.Core.Adcs;
using Certus.Core.ServiceRights;
using Microsoft.Extensions.Logging;

namespace Certus.Adcs.ServiceRights;

/// <summary>
/// The real <see cref="IServiceRightsProbe"/> (issue #440): the three ADCS COM
/// classes activated locally, <see cref="DirectoryRightsReader"/> for the
/// account and the template permissions, and <see cref="CaRoleReader"/> for the
/// CA's own verdict.
///
/// Every call is synchronous COM or LDAP, so each runs on the thread pool, and
/// every failure is mapped to a <see cref="ReadingOutcome"/> here rather than
/// thrown, so the check can report on the rest. Registered in the production
/// host only; the dev host runs <see cref="MockServiceRightsProbe"/>.
/// </summary>
public sealed class AdcsServiceRightsProbe : IServiceRightsProbe
{
    /// <summary>REGDB_E_CLASSNOTREG: the COM class is not registered on this server.</summary>
    private const int ClassNotRegisteredHResult = unchecked((int)0x80040154);

    /// <summary>
    /// DISP_E_MEMBERNOTFOUND, which the troubleshooting guide reports for a
    /// server without RSAT-ADCS-Mgmt, where a class can activate and then fail
    /// to resolve its methods.
    /// </summary>
    private const int MemberNotFoundHResult = unchecked((int)0x80020003);

    private const string RsatRemedy =
        "Install the ADCS Remote Administration Tools on this server " +
        "(Install-WindowsFeature RSAT-ADCS-Mgmt) and restart the service.";

    private readonly ILogger<AdcsServiceRightsProbe> _logger;

    public AdcsServiceRightsProbe(ILogger<AdcsServiceRightsProbe> logger)
    {
        _logger = logger;
    }

    public bool Simulated => false;

    public Task<ComponentsReading> CheckComponentsAsync(CancellationToken cancellationToken = default)
    {
        return Task.Run(() => new ComponentsReading(
        [
            Activate("CertRequest", () => new CertRequestClass()),
            Activate("CertView", () => new CertViewClass()),
            Activate("CertAdmin", () => new CertAdminClass()),
        ]), cancellationToken);
    }

    public Task<PrincipalReading> ReadServicePrincipalAsync(CancellationToken cancellationToken = default)
    {
        return Task.Run(() =>
        {
            var reading = DirectoryRightsReader.ReadServicePrincipal();
            if (reading.Outcome != ReadingOutcome.Ok)
            {
                _logger.LogWarning(
                    "Service rights check: the service's account could not be read ({Outcome}): {Detail}",
                    reading.Outcome, reading.Detail);
            }
            return reading;
        }, cancellationToken);
    }

    public Task<CaRolesReading> ReadCaRolesAsync(
        string caConnectionString,
        CancellationToken cancellationToken = default)
    {
        return Task.Run(() =>
        {
            try
            {
                return new CaRolesReading(ReadingOutcome.Ok, CaRoleReader.ReadMyRoles(caConnectionString));
            }
            catch (Exception ex)
            {
                var reading = ClassifyRolesFailure(ex);
                _logger.LogWarning(
                    ex,
                    "Service rights check: the CA did not report the service's roles ({Outcome}). HRESULT: 0x{HResult:X8}",
                    reading.Outcome, ex.HResult);
                return reading;
            }
        }, cancellationToken);
    }

    public Task<TemplateDaclReading> ReadTemplateDaclAsync(
        string templateName,
        CancellationToken cancellationToken = default)
    {
        return Task.Run(() =>
        {
            var reading = DirectoryRightsReader.ReadTemplateDacl(templateName);
            if (reading.Outcome != ReadingOutcome.Ok)
            {
                _logger.LogWarning(
                    "Service rights check: the permissions of template {Template} could not be read ({Outcome}): {Detail}",
                    templateName, reading.Outcome, reading.Detail);
            }
            return reading;
        }, cancellationToken);
    }

    /// <summary>
    /// Why a refusal of <c>ICertAdmin2::GetMyRoles</c> is ambiguous. The CA
    /// reports roles only to an account holding Read or more, and lab 2019
    /// measured on 2026-09-26 that Request Certificates alone is refused
    /// (issue #440), whatever [MS-CSRA] suggests.
    /// </summary>
    private const string RolesRefusedDetail =
        "The CA refused to report the service's roles. It reports them only to an account holding Read " +
        "or more, and Request Certificates alone is not enough. A CA that refuses remote administration " +
        "altogether (IF_NOREMOTEICERTADMIN) refuses every account the same way.";

    /// <summary>
    /// Maps a failed <c>ICertAdmin2::GetMyRoles</c> to an outcome. Internal for unit tests.
    /// </summary>
    internal static CaRolesReading ClassifyRolesFailure(Exception ex)
    {
        return ex switch
        {
            UnauthorizedAccessException => new CaRolesReading(
                ReadingOutcome.AccessDenied, null, ex.HResult,
                RolesRefusedDetail),
            COMException com when CaAccessDeniedException.IsAccessDenied(com) => new CaRolesReading(
                ReadingOutcome.AccessDenied, null, com.HResult,
                RolesRefusedDetail),
            COMException com when CaUnavailableException.IsRpcUnavailable(com) => new CaRolesReading(
                ReadingOutcome.Unavailable, null, com.HResult,
                "The CA could not be reached over RPC."),
            COMException { HResult: ClassNotRegisteredHResult or MemberNotFoundHResult } com => new CaRolesReading(
                ReadingOutcome.NotRegistered, null, com.HResult,
                "The CertAdmin COM class is missing or incomplete on this server. " + RsatRemedy),
            _ => new CaRolesReading(
                ReadingOutcome.Failed, null, ex.HResult,
                $"The CA did not report the service's roles: {ex.Message}"),
        };
    }

    private ComponentReading Activate(string name, Func<object> create)
    {
        object? instance = null;
        try
        {
            instance = create();
            return new ComponentReading(name, ReadingOutcome.Ok);
        }
        catch (COMException ex) when (ex.HResult == ClassNotRegisteredHResult)
        {
            _logger.LogWarning(ex, "Service rights check: the {Class} COM class is not registered", name);
            return new ComponentReading(
                name, ReadingOutcome.NotRegistered, ex.HResult,
                $"The {name} COM class is not registered on this server. {RsatRemedy}");
        }
        catch (Exception ex)
        {
            _logger.LogWarning(ex, "Service rights check: the {Class} COM class did not activate", name);
            return new ComponentReading(
                name, ReadingOutcome.Failed, ex.HResult,
                $"The {name} COM class did not activate: {ex.Message}");
        }
        finally
        {
            if (instance != null && Marshal.IsComObject(instance))
                Marshal.FinalReleaseComObject(instance);
        }
    }
}
