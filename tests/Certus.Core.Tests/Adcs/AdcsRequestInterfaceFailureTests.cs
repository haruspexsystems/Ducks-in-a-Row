using System.Runtime.InteropServices;
using Certus.Adcs;
using Certus.Core.Adcs;

namespace Certus.Core.Tests.Adcs;

/// <summary>
/// How a failed template list read, CA chain read or certificate collection
/// leaves <c>AdcsClient</c> (issues #467, #476 and #477). All three go through
/// the CA's request interface, which answers an account without Request
/// Certificates with CERTSRV_E_ENROLL_DENIED rather than E_ACCESSDENIED
/// (lab 2019 for #440, lab 2025 for #469). The template and chain reads caught
/// COMException alone, so a refusal left as a generic failure and an
/// UnauthorizedAccessException escaped unwrapped; the collection tested
/// E_ACCESSDENIED alone, so the refusal the lab measured left as a plain
/// InvalidOperationException and the finalize demoted an order whose
/// certificate was live at the CA.
///
/// The Submit joined them for #566: lab 2019b measured it throwing
/// CERTSRV_E_ENROLL_DENIED itself under Read without Request Certificates, where
/// its catch tested E_ACCESSDENIED alone. It is classified only before the
/// Submit returns, so the "submit" path here is that side of the line.
///
/// The COM calls themselves need a live CA, so these pin the classifier each
/// path's catch decides with, and the message each path carries.
/// </summary>
public class AdcsRequestInterfaceFailureTests
{
    public static TheoryData<string, string> Paths => new()
    {
        { "templates", CaAccessDeniedException.TemplateReadPermissionMessage },
        { "chain", CaAccessDeniedException.ChainReadPermissionMessage },
        { "collect", CaAccessDeniedException.CollectPermissionMessage },
        { "connect", CaAccessDeniedException.ConnectPermissionMessage },
        { "submit", CaAccessDeniedException.EnrollPermissionMessage },
    };

    public static TheoryData<string> PathNames => new() { "templates", "chain", "collect", "connect", "submit" };

    private static Exception? Classify(string path, Exception ex) => path switch
    {
        "templates" => AdcsClient.ClassifyTemplateReadFailure(ex),
        "chain" => AdcsClient.ClassifyChainReadFailure(ex),
        "collect" => AdcsClient.ClassifyCollectFailure(ex),
        "connect" => AdcsClient.ClassifyConnectFailure(ex),
        "submit" => AdcsClient.ClassifySubmitFailure(ex, submitReturned: false),
        _ => throw new ArgumentOutOfRangeException(nameof(path), path, null),
    };

    [Theory]
    [InlineData("enroll denied")]
    [InlineData("access denied")]
    [InlineData("access denied through dynamic")]
    [InlineData("rpc unavailable")]
    public void PastTheSubmit_NothingIsClassified(string shape)
    {
        Exception ex = shape switch
        {
            "enroll denied" => new COMException("enroll denied", CaStatusCode.EnrollDenied),
            "access denied" => new COMException("denied", CaAccessDeniedException.AccessDeniedHResult),
            "access denied through dynamic" => new UnauthorizedAccessException(),
            "rpc unavailable" => new COMException("rpc", CaUnavailableException.RpcServerUnavailableHResult),
            _ => throw new ArgumentOutOfRangeException(nameof(shape), shape, null),
        };

        // Once Submit has returned, the CA holds a request for this CSR. A typed
        // exception would tell the finalize nothing reached the CA and let it
        // release a claim on an order whose request is live, so a refusal or an
        // outage out of GetRequestId or GetDispositionMessage stays a plain
        // failure, as it was before #566.
        AdcsClient.ClassifySubmitFailure(ex, submitReturned: true).Should().BeNull();
    }

    [Theory]
    [MemberData(nameof(Paths))]
    public void EnrollDenied_IsARefusal_CarryingThePathsOwnMessage(string path, string message)
    {
        // The lab's answer to an account holding Read without Request
        // Certificates, for every one of these reads. The case all three issues
        // are about.
        var com = new COMException("enroll denied", CaStatusCode.EnrollDenied);

        var mapped = Classify(path, com);

        mapped.Should().BeOfType<CaAccessDeniedException>()
            .Which.Message.Should().Be(message);
        mapped!.InnerException.Should().BeSameAs(com);
    }

    [Theory]
    [MemberData(nameof(Paths))]
    public void AnAccessDeniedHResult_IsARefusal(string path, string message)
    {
        Classify(path, new COMException("denied", CaAccessDeniedException.AccessDeniedHResult))
            .Should().BeOfType<CaAccessDeniedException>()
            .Which.Message.Should().Be(message);
    }

    [Theory]
    [MemberData(nameof(Paths))]
    public void AnAccessDeniedThroughDynamic_IsARefusal(string path, string message)
    {
        // The usual shape of E_ACCESSDENIED through IDispatch, which the template
        // and chain reads' COMException catch never saw at all.
        Classify(path, new UnauthorizedAccessException())
            .Should().BeOfType<CaAccessDeniedException>()
            .Which.Message.Should().Be(message);
    }

    [Theory]
    [MemberData(nameof(PathNames))]
    public void RpcUnavailable_IsAnOutage_NotARefusal(string path)
    {
        Classify(path, new COMException("rpc", CaUnavailableException.RpcServerUnavailableHResult))
            .Should().BeOfType<CaUnavailableException>();
    }

    [Theory]
    [MemberData(nameof(PathNames))]
    public void AnyOtherComFailure_IsLeftToThePath(string path)
    {
        // Null means the path's own COMException arm answers it, as a plain
        // failure, which is what it did before for everything but an outage.
        Classify(path, new COMException("odd", unchecked((int)0x80004005))).Should().BeNull();
    }

    [Theory]
    [MemberData(nameof(PathNames))]
    public void ANonComFailure_IsLeftToThePath(string path)
    {
        // A chain that will not parse, or a dispatch the binder cannot resolve,
        // says nothing about the service's rights and must not read as a
        // refusal.
        Classify(path, new FormatException("not base64")).Should().BeNull();
        Classify(path, new InvalidOperationException("no signing certificate")).Should().BeNull();
    }

    [Theory]
    [InlineData(CaAccessDeniedException.TemplateReadPermissionMessage)]
    [InlineData(CaAccessDeniedException.ChainReadPermissionMessage)]
    [InlineData(CaAccessDeniedException.CollectPermissionMessage)]
    [InlineData(CaAccessDeniedException.EnrollPermissionMessage)]
    public void TheMessage_NamesRequestCertificates_NotRead(string message)
    {
        // Every one of these reads goes through the request interface. Telling an
        // operator to grant Read, which CollectPermissionMessage did until #477,
        // fixes nothing: lab 2025 refused the collection under Read alone and
        // answered it to Request Certificates alone.
        message.Should().Contain("'Request Certificates'");
        message.Should().NotContain("'Read'");
        message.Should().Contain("IF_NOREMOTEICERTREQUEST",
            "a CA refusing remote requests answers every account the same way");
    }

    [Fact]
    public void TheCollectMessage_SpeaksToBothOfItsCallers()
    {
        // The ACME finalize and sweep leave the order to be collected; the
        // server's own HTTPS enrolment has no order and has to be run again.
        CaAccessDeniedException.CollectPermissionMessage.Should()
            .Contain("ACME order").And.Contain("HTTPS certificate enrolment");
    }

    [Fact]
    public void ThePathMessages_AreDistinct()
    {
        // One message per path, so a log line or a 503 names what stopped.
        new[]
        {
            CaAccessDeniedException.TemplateReadPermissionMessage,
            CaAccessDeniedException.ChainReadPermissionMessage,
            CaAccessDeniedException.CollectPermissionMessage,
            CaAccessDeniedException.ConnectPermissionMessage,
            CaAccessDeniedException.CrlReadPermissionMessage,
            CaAccessDeniedException.EnrollPermissionMessage,
        }.Should().OnlyHaveUniqueItems();
    }
}
