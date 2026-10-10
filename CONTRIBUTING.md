# Contributing to Ducks in a Row

Thanks for your interest. Ducks in a Row is **source available** under the
[Business Source License 1.1](LICENSE), not OSI open source. You are welcome to
read the source, build it, and run it within the terms of that license.

**Pull requests are not accepted.**

## Ways to help

- **Report a bug** — open an issue with your version, your environment (Windows
  Server version, ADCS setup), what you expected, and what happened.
- **Request a feature** — open an issue describing the problem you want solved,
  not just the solution you have in mind.
- **Report a vulnerability** — do not open an issue. Follow
  [SECURITY.md](SECURITY.md) and email security@haruspex.systems.

Questions and general discussion go through the channels in
[SUPPORT.md](SUPPORT.md).

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

## ADCS COM interop

The code that talks to ADCS uses a deliberate late-bound IDispatch design rather
than typed COM interfaces. If you work in `Certus.Adcs`, read the COM notes in
the repository before changing anything there, because typed interface
declarations are blocked on purpose.
