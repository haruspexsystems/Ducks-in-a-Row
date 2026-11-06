using Certus.Core.Configuration;
using Microsoft.Extensions.Configuration;

namespace Certus.Core.Tests.Configuration;

/// <summary>
/// The defaults of <see cref="AuthOptions"/> that a release promises (issue #633):
/// the Kerberos only switch ships off, because turning it on needs a service
/// principal name the operator has registered, and binds from the Auth section
/// like the rest.
/// </summary>
public class AuthOptionsTests
{
    [Fact]
    public void RequireKerberos_IsOffByDefault()
    {
        new AuthOptions().RequireKerberos.Should().BeFalse(
            "on by default is a later decision, once the setup wizard can tell the operator " +
            "whether their browser and service principal name will work (issue #633)");
    }

    [Fact]
    public void RequireKerberos_BindsFromTheAuthSection()
    {
        var configuration = new ConfigurationBuilder()
            .AddInMemoryCollection(new Dictionary<string, string?>
            {
                ["Auth:RequireKerberos"] = "true",
            })
            .Build();

        var options = configuration.GetSection(AuthOptions.SectionName).Get<AuthOptions>();

        options!.RequireKerberos.Should().BeTrue();
        options.Mode.Should().Be(AuthOptions.ModeNegotiate, "the other defaults are untouched by the new key");
    }
}
