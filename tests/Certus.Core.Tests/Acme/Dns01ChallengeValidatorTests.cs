using System.Security.Cryptography;
using System.Text;
using Certus.Core.Acme.Crypto;
using Certus.Core.Acme.Services;
using DnsClient;
using DnsClient.Protocol;
using Microsoft.Extensions.Logging.Abstractions;
using NSubstitute;

namespace Certus.Core.Tests.Acme;

public class Dns01ChallengeValidatorTests
{
    private const string TestToken = "test-token-abc123";
    private const string TestThumbprint = "test-thumbprint-xyz";
    private const string TestDomain = "example.com";

    private readonly ILookupClient _mockDns = Substitute.For<ILookupClient>();
    private readonly Dns01ChallengeValidator _sut;

    // Precompute the expected TXT record value
    private static readonly string ExpectedTxtValue = ComputeExpectedDns01Value(TestToken, TestThumbprint);

    public Dns01ChallengeValidatorTests()
    {
        _sut = new Dns01ChallengeValidator(_mockDns, NullLogger<Dns01ChallengeValidator>.Instance);
    }

    [Fact]
    public async Task Validate_CorrectTxtRecord_Succeeds()
    {
        SetupDnsResponse($"_acme-challenge.{TestDomain}", ExpectedTxtValue);

        var result = await _sut.ValidateAsync(TestDomain, TestToken, TestThumbprint);

        result.IsValid.Should().BeTrue();
    }

    [Fact]
    public async Task Validate_WrongTxtValue_Fails()
    {
        SetupDnsResponse($"_acme-challenge.{TestDomain}", "wrong-value");

        var result = await _sut.ValidateAsync(TestDomain, TestToken, TestThumbprint);

        result.IsValid.Should().BeFalse();
        result.Transient.Should().BeFalse(); // a wrong answer is genuine, not retryable
        result.ErrorDetail.Should().Contain("does not contain the expected value");
    }

    [Fact]
    public async Task Validate_NoTxtRecords_Fails()
    {
        SetupEmptyDnsResponse($"_acme-challenge.{TestDomain}");

        var result = await _sut.ValidateAsync(TestDomain, TestToken, TestThumbprint);

        result.IsValid.Should().BeFalse();
        result.Transient.Should().BeFalse(); // record genuinely absent, not a transport error
        result.ErrorDetail.Should().Contain("No TXT records");
    }

    [Fact]
    public async Task Validate_DnsError_Fails()
    {
        SetupDnsError($"_acme-challenge.{TestDomain}", "NXDOMAIN");

        var result = await _sut.ValidateAsync(TestDomain, TestToken, TestThumbprint);

        result.IsValid.Should().BeFalse();
        result.Transient.Should().BeTrue(); // a resolver error is transport level — retry it
        result.ErrorDetail.Should().Contain("failed");
    }

    [Fact]
    public async Task Validate_WildcardDomain_QueriesBaseDomain()
    {
        // For *.example.com, the TXT record should be at _acme-challenge.example.com
        SetupDnsResponse($"_acme-challenge.{TestDomain}", ExpectedTxtValue);

        var result = await _sut.ValidateAsync($"*.{TestDomain}", TestToken, TestThumbprint);

        result.IsValid.Should().BeTrue();
        // Verify it queried _acme-challenge.example.com, not _acme-challenge.*.example.com
        await _mockDns.Received().QueryAsync(
            $"_acme-challenge.{TestDomain}",
            QueryType.TXT,
            QueryClass.IN,
            Arg.Any<CancellationToken>());
    }

    [Fact]
    public async Task Validate_MultipleTxtRecords_MatchesCorrectOne()
    {
        // Setup response with multiple TXT records, only one matching
        SetupDnsResponse($"_acme-challenge.{TestDomain}",
            "wrong-value-1", ExpectedTxtValue, "wrong-value-2");

        var result = await _sut.ValidateAsync(TestDomain, TestToken, TestThumbprint);

        result.IsValid.Should().BeTrue();
    }

    [Fact]
    public void ChallengeType_IsDns01()
    {
        _sut.ChallengeType.Should().Be("dns-01");
    }

    #region Helpers

    private static string ComputeExpectedDns01Value(string token, string thumbprint)
    {
        var keyAuth = $"{token}.{thumbprint}";
        var digest = SHA256.HashData(Encoding.UTF8.GetBytes(keyAuth));
        return JwsService.Base64UrlEncode(digest);
    }

    private void SetupDnsResponse(string queryName, params string[] txtValues)
    {
        var response = Substitute.For<IDnsQueryResponse>();
        response.HasError.Returns(false);

        var answers = new List<DnsResourceRecord>();
        foreach (var value in txtValues)
        {
            var info = new ResourceRecordInfo(queryName, ResourceRecordType.TXT, QueryClass.IN, 300, 0);
            var txtRecord = new TxtRecord(info, new[] { value }, new[] { value });
            answers.Add(txtRecord);
        }

        response.Answers.Returns(new DnsAnswers(answers, answers.Count));

        _mockDns.QueryAsync(queryName, QueryType.TXT, QueryClass.IN, Arg.Any<CancellationToken>())
            .Returns(response);
    }

    private void SetupEmptyDnsResponse(string queryName)
    {
        var response = Substitute.For<IDnsQueryResponse>();
        response.HasError.Returns(false);
        response.Answers.Returns(new DnsAnswers(new List<DnsResourceRecord>(), 0));

        _mockDns.QueryAsync(queryName, QueryType.TXT, QueryClass.IN, Arg.Any<CancellationToken>())
            .Returns(response);
    }

    private void SetupDnsError(string queryName, string errorMessage)
    {
        var response = Substitute.For<IDnsQueryResponse>();
        response.HasError.Returns(true);
        response.ErrorMessage.Returns(errorMessage);
        response.Answers.Returns(new DnsAnswers(new List<DnsResourceRecord>(), 0));

        _mockDns.QueryAsync(queryName, QueryType.TXT, QueryClass.IN, Arg.Any<CancellationToken>())
            .Returns(response);
    }

    /// <summary>
    /// Minimal DnsAnswers implementation to satisfy the tests.
    /// </summary>
    private sealed class DnsAnswers : IReadOnlyList<DnsResourceRecord>
    {
        private readonly IReadOnlyList<DnsResourceRecord> _records;
        public DnsAnswers(IReadOnlyList<DnsResourceRecord> records, int count)
        {
            _records = records;
            Count = count;
        }
        public int Count { get; }
        public DnsResourceRecord this[int index] => _records[index];
        public IEnumerator<DnsResourceRecord> GetEnumerator() => _records.GetEnumerator();
        System.Collections.IEnumerator System.Collections.IEnumerable.GetEnumerator() => GetEnumerator();
    }

    #endregion
}
