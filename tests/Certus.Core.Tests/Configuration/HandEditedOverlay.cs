using System.Text.Encodings.Web;
using System.Text.Json;
using System.Text.Json.Nodes;
using Certus.Core.Configuration;
using Microsoft.Extensions.Configuration;

namespace Certus.Core.Tests.Configuration;

/// <summary>
/// The keys an administrator adds to settings.json by hand, the way the docs tell them
/// to (issue #550). Every service write used to rewrite the file from the keys it
/// manages alone, so each of these went at the first save, and the next restart fell
/// back without a word: the admin group to BUILTIN\Administrators, private range
/// blocking off, webhook alerting off.
///
/// <para>
/// One key sits in each place a save has to look after: at the top level (Auth), at
/// the top level in the colon form docs/hardening.md shows
/// (Certus:Acme:ChallengeValidation), inside the Certus section beside the managed keys
/// (RateLimiting), and inside a block the dashboard manages (the webhook, under
/// Alerts). The admin group carries a backslash and a non ASCII letter, as a German
/// domain's built in group name does, so a value that is re-encoded rather than kept
/// is visible in the file.
/// </para>
/// </summary>
internal static class HandEditedOverlay
{
    public const string AdminGroup = "CORP\\Domänen-Admins";
    public const string WebhookUrl = "https://hooks.corp.example.com/ducks?token=abc&channel=pki";

    private static readonly JsonSerializerOptions WriteOptions = new()
    {
        WriteIndented = true,
        Encoder = JavaScriptEncoder.UnsafeRelaxedJsonEscaping,
    };

    /// <summary>
    /// Add the hand keys to the overlay at <paramref name="path"/>, keeping whatever it
    /// already holds, or create it with only them. Written with the developer's own
    /// account, which the service trusts as the process identity.
    /// </summary>
    public static void AddTo(string path)
    {
        var root = File.Exists(path)
            ? JsonNode.Parse(File.ReadAllText(path))!.AsObject()
            : new JsonObject();

        if (root["Certus"] is not JsonObject certus)
        {
            certus = new JsonObject();
            root["Certus"] = certus;
        }

        certus["RateLimiting"] = new JsonObject { ["NewOrderLimit"] = 5 };

        if (certus["Alerts"] is not JsonObject alerts)
        {
            alerts = new JsonObject();
            certus["Alerts"] = alerts;
        }

        alerts["Webhook"] = new JsonObject { ["Url"] = WebhookUrl };

        root["Certus:Acme:ChallengeValidation"] = new JsonObject
        {
            ["BlockPrivateRanges"] = true,
            ["AdditionalBlockedCidrs"] = new JsonArray("100.64.0.0/10"),
        };
        root["Auth"] = new JsonObject { ["AdminGroup"] = AdminGroup };

        File.WriteAllText(path, root.ToJsonString(WriteOptions));
    }

    /// <summary>
    /// Read the overlay at <paramref name="path"/> the way the service host does at
    /// startup, and assert every hand key is still in force.
    /// </summary>
    public static void ShouldStillBeInForce(string path)
    {
        Path.GetFileName(path).Should().Be(CertusPaths.SettingsOverlayFileName,
            "the startup read finds the overlay by its file name in the data folder");

        using var configuration = new ConfigurationManager();
        ((IConfigurationBuilder)configuration)
            .AddSettingsOverlay(Path.GetDirectoryName(path)!)
            .IsTrusted.Should().BeTrue();

        configuration["Auth:AdminGroup"].Should().Be(AdminGroup);
        // The JSON provider renders a boolean as "True"; the binder reads either case.
        configuration["Certus:Acme:ChallengeValidation:BlockPrivateRanges"].Should().BeEquivalentTo("true");
        configuration["Certus:Acme:ChallengeValidation:AdditionalBlockedCidrs:0"].Should().Be("100.64.0.0/10");
        configuration["Certus:RateLimiting:NewOrderLimit"].Should().Be("5");
        configuration["Certus:Alerts:Webhook:Url"].Should().Be(WebhookUrl);
    }
}
