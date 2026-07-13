# Ducks in a Row

> Make ADCS work like Let's Encrypt for your internal network.

**Ducks in a Row** is an ACME-to-ADCS proxy that brings modern, standards-based
certificate lifecycle management to organizations running Active Directory
Certificate Services. Any machine, domain-joined or not, can use a standard ACME
client to request certificates from an internal ADCS certificate authority.

## Status

**Version 0.9.0-beta.1.** The feature set is complete and in real-world testing
before a 1.0 release. The installer is not code signed yet. Windows SmartScreen and
Microsoft Defender will warn you when you run it. This is expected. Verify the
download against the SHA256 checksum on the release page. A signed 1.0 will
follow this beta. You can get it from the public repository at
https://github.com/haruspexsystems/Ducks-in-a-Row.

## What it does

Point any ACME client at Ducks in a Row and it proxies the request to your
internal ADCS CA, maps the order to the right certificate template, validates
ownership with a standard ACME challenge, and hands back the issued certificate.
The dashboard then tracks every certificate to expiry and alerts you before it
expires.

## Features

- **ACME server:** RFC 8555 compliant, proxying enrolment to ADCS.
- **Directory per template:** `/acme/{template}/directory` exposes each ADCS
  template as its own ACME endpoint.
- **All three challenge types:** HTTP-01, DNS-01, and TLS-ALPN-01.
- **Dashboard:** a React interface showing the full certificate inventory read
  from the ADCS CA database.
- **Expiry alerts:** email (SMTP) and webhook notifications before certificates
  expire.
- **Setup wizard:** guided setup in the browser, from zero to working in minutes.
- **Windows Integrated Authentication:** the dashboard is limited to a configured
  administrator group.

## Privacy

Ducks in a Row collects **no telemetry. Ever.** It runs entirely on your own
servers and never sends data back to us or anyone else. The only network calls
it makes are to systems you configure: your ADCS certificate authority, your
SMTP or webhook endpoints for alerts, and the domains and DNS it checks during a
challenge. Fonts and other assets are bundled with the app, so the dashboard
makes no third-party requests. A tool that sits in front of your certificate
authority should not be watching you, and this one does not.

## Install

Download the installer from the
[latest release](https://github.com/haruspexsystems/Ducks-in-a-Row/releases) and run it
on the server that will host Ducks in a Row, then complete the browser-based
setup wizard. `Ducks-in-a-Row-Setup.exe` installs the ASP.NET Core runtime for
you (offline capable); the bare MSI needs the runtime already present.

This is a beta and the installer is not code signed, so SmartScreen and
Defender will warn you when you run it. Verify the download against the
SHA256 checksum published on the release page first. See the documentation
for a full walkthrough.

## Prerequisites

- Windows Server (required for ADCS COM interop).
- Domain-joined (required for DCOM authentication to the CA).
- Reachable ADCS certificate authority with the templates you want to expose.

## License

Ducks in a Row is published under the [Business Source License 1.1](LICENSE).
It is **source available**, not OSI open source: free to run in production to
manage your own or your customers' certificates, and it converts to the
[Apache License 2.0](https://www.apache.org/licenses/LICENSE-2.0) four years
after each version is released. See [LICENSING.md](LICENSING.md) for a
plain-language summary. A commercial license is required to resell or host it
as a competing product, or to use the paid tier.

Copyright © 2026 Haruspex Systems B.V. "Ducks in a Row" is a trademark of
Haruspex Systems B.V.

---

## Building from source

For contributors and auditors. End users should install from the release above
rather than build.

### Toolchain

- [.NET 8 SDK](https://dotnet.microsoft.com/download/dotnet/8.0)
- [Node.js](https://nodejs.org/) (for the React frontend)
- [WiX Toolset](https://wixtoolset.org/) (`dotnet tool install --global wix`,
  for the MSI and the setup bundle). `build.ps1` installs the required WiX
  extensions (`WixToolset.Firewall.wixext`, `WixToolset.UI.wixext`,
  `WixToolset.Util.wixext`, plus `WixToolset.Bal.wixext` and
  `WixToolset.Netfx.wixext` for the bundle) globally on first run.

### Build, test, run

```bash
dotnet restore
dotnet build
dotnet test
dotnet run --project src/Certus.Web   # dev host; health at http://localhost:5000/health
```

To produce the installers, run `./build.ps1`. It builds the frontend, publishes
the service, packages the MSI, and wraps it in `artifacts/Ducks-in-a-Row-Setup.exe`,
a bootstrapper that embeds the ASP.NET Core Hosting Bundle so offline servers
install with one file. The roughly 100 MB runtime exe is downloaded once, hash
verified, and cached in `installer/redist/`.

### Project structure

| Project | Purpose |
|---------|---------|
| `Certus.Core` | Domain models, ACME services, alerts, EF Core data layer |
| `Certus.Adcs` | ADCS COM interop via late-bound IDispatch |
| `Certus.Web` | ASP.NET Core host: ACME endpoints and Dashboard API |
| `Certus.Service` | Windows Service wrapper for production deployment |
| `Certus.*.Tests` | Unit and integration tests |
