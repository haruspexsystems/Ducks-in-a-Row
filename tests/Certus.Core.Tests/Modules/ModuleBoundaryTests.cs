using Certus.Core.Modules;
using Certus.Modules;

namespace Certus.Core.Tests.Modules;

/// <summary>
/// The boundary copy (licence design section 5): the core copies a module's evaluation into its own
/// record, capping strings at 200 characters and arrays at 64 entries and stripping control
/// characters, so a module's object never reaches a serializer or a view as its own.
/// </summary>
public class ModuleBoundaryTests
{
    [Fact]
    public void Copy_CapsStrings_CapsArrays_AndStripsControlCharacters()
    {
        var evaluation = new LicenceEvaluation(
            LicenceStatus.Valid,
            "ok\r\ninjected\tline",
            new string('x', 500),
            "standard",
            Enumerable.Range(0, 100).Select(i => $"feature-{i}").ToArray(),
            3,
            "Acme BV",
            "CUST-1",
            null, null, null, null, 30,
            Enumerable.Range(0, 100).Select(i => $"forest-{i}").ToArray(),
            "forest",
            false, false, NoticeStage.None, false);

        var snapshot = ModuleBoundary.Copy(evaluation);

        snapshot.ReasonCode.Should().NotContainAny("\r", "\n", "\t");
        snapshot.LicenceId!.Length.Should().Be(200);
        snapshot.Features.Count.Should().Be(64);
        snapshot.BoundForests.Count.Should().Be(64);
        snapshot.Status.Should().Be(LicenceStatus.Valid);
    }
}
