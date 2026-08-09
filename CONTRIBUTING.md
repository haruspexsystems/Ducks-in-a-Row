# Contributing to Ducks in a Row

Thanks for your interest. Ducks in a Row is **source available** under the
[Business Source License 1.1](LICENSE), not OSI open source. You are welcome to
read the source, file issues, and propose changes within that license.

## Ways to help

- **Report a bug** — open an issue with your version, your environment (Windows
  Server version, ADCS setup), what you expected, and what happened.
- **Request a feature** — open an issue describing the problem you want solved,
  not just the solution you have in mind.
- **Report a vulnerability** — do not open an issue. Follow
  [SECURITY.md](SECURITY.md) and email security@haruspex.systems.
- **Send a pull request** — see below, but read the note first.

## Contributor License Agreement

Ducks in a Row is an open core product. To keep the project relicensable and
commercially viable, every contributor will need to agree to our
[Contributor License Agreement](CLA.md) before we can merge their work.

**Code contributions (pull requests) are not yet being accepted** while the CLA
is under legal review by Haruspex Systems B.V. Bug reports and feature
discussion are welcome any time — see [SUPPORT.md](SUPPORT.md). Once the CLA is
finalized, we'll enable the CLA Assistant bot and start merging pull requests;
this note will be removed at that point.

## Development setup

See [docs/dev-setup.md](docs/dev-setup.md) for the full toolchain. In short you
need the .NET 10 SDK, Node.js for the React frontend, and the WiX Toolset for the
installer.

```bash
dotnet restore
dotnet build
dotnet test
dotnet run --project src/Certus.Web
```

## Pull request expectations

- Keep each pull request focused on one change.
- All existing tests must pass, and new behaviour should come with tests.
- The frontend must build cleanly if you touch it.
- CI must be green before we review.
- Match the style of the surrounding code; `.editorconfig` covers formatting.

## ADCS COM interop

The code that talks to ADCS uses a deliberate late-bound IDispatch design rather
than typed COM interfaces. If you work in `Certus.Adcs`, read the COM notes in
the repository before changing anything there, because typed interface
declarations are blocked on purpose.
