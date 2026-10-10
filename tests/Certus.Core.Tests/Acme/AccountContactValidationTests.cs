using Certus.Core.Acme.Services;

namespace Certus.Core.Tests.Acme;

/// <summary>
/// Unit tests for <see cref="AccountService.ValidateContacts"/>, the size guard both
/// new-account and the account update endpoint (RFC 8555 §7.3.2) run before storing a
/// contact list. It is a bound on what can be written, not RFC §7.3 contact validation:
/// nothing here asserts anything about the scheme or the address, deliberately.
/// </summary>
public class AccountContactValidationTests
{
    [Fact]
    public void NullContact_IsAccepted()
    {
        // Absent means "no change" at the update endpoint and "no contacts" at
        // new-account. Neither is a refusal.
        AccountService.ValidateContacts(null, out var error).Should().BeTrue();
        error.Should().BeNull();
    }

    [Fact]
    public void EmptyContact_IsAccepted()
    {
        // An empty array is how a client clears its contacts (§7.3.2).
        AccountService.ValidateContacts(Array.Empty<string>(), out var error).Should().BeTrue();
        error.Should().BeNull();
    }

    [Fact]
    public void OrdinaryContact_IsAccepted()
    {
        var contact = new[] { "mailto:admin@example.com", "mailto:ops@example.com" };

        AccountService.ValidateContacts(contact, out var error).Should().BeTrue();
        error.Should().BeNull();
    }

    [Fact]
    public void ExactlyTheEntryCap_IsAccepted()
    {
        var contact = Enumerable.Range(0, AccountService.MaxContactEntries)
            .Select(i => $"mailto:user{i}@example.com")
            .ToArray();

        AccountService.ValidateContacts(contact, out var error).Should().BeTrue(
            "the cap is inclusive; only the entry past it is refused");
        error.Should().BeNull();
    }

    [Fact]
    public void OneOverTheEntryCap_IsRefused()
    {
        var contact = Enumerable.Range(0, AccountService.MaxContactEntries + 1)
            .Select(i => $"mailto:user{i}@example.com")
            .ToArray();

        AccountService.ValidateContacts(contact, out var error).Should().BeFalse();
        error.Should().NotBeNull();
        error.Should().Contain(AccountService.MaxContactEntries.ToString(),
            "the refusal has to say what the limit is, or the client cannot comply");
    }

    [Fact]
    public void EntryAtTheLengthCap_IsAccepted()
    {
        var contact = new[] { new string('a', AccountService.MaxContactLength) };

        AccountService.ValidateContacts(contact, out var error).Should().BeTrue();
        error.Should().BeNull();
    }

    [Fact]
    public void EntryOneOverTheLengthCap_IsRefused()
    {
        var contact = new[] { new string('a', AccountService.MaxContactLength + 1) };

        AccountService.ValidateContacts(contact, out var error).Should().BeFalse();
        error.Should().NotBeNull();
        error.Should().Contain(AccountService.MaxContactLength.ToString());
    }

    [Fact]
    public void OverlongEntry_IsRefused_WhereverItSits()
    {
        // The scan does not stop at the first entry: a long value hidden behind
        // several short ones is the shape an abuser would actually send.
        var contact = new[]
        {
            "mailto:first@example.com",
            "mailto:second@example.com",
            new string('a', AccountService.MaxContactLength + 1),
        };

        AccountService.ValidateContacts(contact, out var error).Should().BeFalse();
        error.Should().Contain("3", "the refusal names which entry was the problem");
    }

    [Theory]
    [InlineData("")]
    [InlineData("   ")]
    public void BlankEntry_IsRefused(string blank)
    {
        var contact = new[] { "mailto:real@example.com", blank };

        AccountService.ValidateContacts(contact, out var error).Should().BeFalse();
        error.Should().NotBeNull();
    }
}
