# Ducks in a Row

If you run Active Directory Certificate Services (ADCS) with a small team,
certificate renewals tend to live in scripts and calendar reminders.

**Ducks in a Row** is one Windows service in front of the ADCS certificate
authority you already run. Your machines, domain joined or not, request and
renew their own certificates from it with a standard ACME client.

- Expiry alerts by email and webhook for every certificate in your CA's
  inventory, free.
- Pull, not push: each machine asks for its own certificate, so no credentials
  for your servers are stored anywhere and Ducks in a Row needs no rights on
  them.
- One scoped external account binding credential per team: you set the names a
  team may request, and the team serves itself within them.
- Nothing phones home. Ever.
- Your existing ADCS trust chain stays exactly as it is.

## Status

**Generally available since version 1.0.0.** The installers, and every `.exe`
and `.dll` they install, are code signed by Haruspex Systems B.V. and
timestamped, so Windows names the publisher when it asks for permission to
install. [Check the download](docs/installation.md#check-the-download) before
you run it. You can get it from the public repository at
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
- **Four challenge types:** HTTP-01, DNS-01, TLS-ALPN-01, and
  `device-attest-01` for hardware attested devices.
- **External account binding:** pre-issued credentials gate who may register,
  with off, optional, and required modes, show-once secrets, revocation that
  suspends a credential's accounts, per-credential domain namespaces that
  limit what each credential's accounts may order, and an optional AD
  principal link that records who each credential was issued to.
- **Allowed domains:** an optional policy restricting which DNS names ACME
  clients may order, each entry covering a domain and its subdomains, enforced
  immediately and surfaced on the dashboard activity feed.
- **Device attestation:** ACME `device-attest-01` issues to hardware attested
  devices that present a permanent identifier instead of a DNS name. Off by
  default and fails closed, with an allowlist and pinned trust anchors. Apple
  attestation in this release.
- **Dashboard:** a React interface showing the full certificate inventory,
  synced from the ADCS CA database on a schedule.
- **Revocation:** revoke from the dashboard, within a capability ceiling no
  setting can raise and a scope you choose. ACME clients can revoke their own
  certificates per RFC 8555.
- **Renews its own TLS certificate:** the server enrols and renews the
  certificate it serves the dashboard and ACME endpoints with.
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

The [documentation](docs/README.md) has the full walkthrough: a
[quickstart](docs/quickstart.md), the
[system requirements](docs/system-requirements.md), and a
[troubleshooting guide](docs/troubleshooting.md).

Both installers are code signed by Haruspex Systems B.V. and timestamped. Check
the signature, and the SHA256 checksum published on the release page, before you
run either one; [installation](docs/installation.md#check-the-download) shows
how. Windows SmartScreen may still warn about a new release while the signing
certificate builds up a reputation with Microsoft. If it does, **More info**
should name Haruspex Systems B.V. as the publisher. If it names anyone else, or
an unknown publisher, do not run the file. See the documentation for a full
walkthrough.

Every release also carries a software bill of materials,
`Ducks-in-a-Row-<version>.cdx.json`, in CycloneDX 1.6 format and listed in the
same `SHA256SUMS` file. It covers the NuGet packages the service is built from,
the npm packages the dashboard is built from, and the ASP.NET Core Hosting
Bundle that `Ducks-in-a-Row-Setup.exe` embeds. Build tooling is left out, apart
from about fifteen packages that only the database design tools use: those are
listed although the service does not ship them, because the filter that would
remove them also removes packages it does use. The bill errs toward listing too
much rather than too little.

## Prerequisites

- Windows Server (required for ADCS COM interop). Verified on Server 2019 and
  Server 2025. **On Server 2022, install current Windows updates first**: the
  .NET 10 runtime requires Control-flow Enforcement Technology there, and a
  Server 2022 installation that has not been serviced since early 2022 does not
  provide it. Build 20348.587 is confirmed too old; check yours with `winver`.
  Server 2019 predates the requirement and is unaffected; Server 2025 ships
  with it. See Troubleshooting below for what the failure looks like.
- Domain-joined (required for DCOM authentication to the CA).
- Reachable ADCS certificate authority with the templates you want to expose.

## Troubleshooting the install

**MSI Error 1920, "Verify that you have sufficient privileges to start system
services".** This almost never means what it says. The installer is already
elevated; the message appears because the service started and then exited
before it could signal Windows. The real error is in the service's own log at
`C:\ProgramData\Ducks in a Row\logs\ducks-<date>.log`. Read that first.

If the log is empty or absent, the service crashed before its logger started.
On Server 2022 the usual cause is the missing Control-flow Enforcement support
described under Prerequisites: the process faults inside `coreclr.dll` with
exception code `0x80131506`, and running the service executable directly from
a command prompt prints the actual reason. Install current Windows updates and
retry.

## License

Ducks in a Row is published under the [Business Source License 1.1](LICENSE).
It is **source available**, not OSI open source: free to run in production to
manage your own or your customers' certificates, and it converts to the
[Apache License 2.0](https://www.apache.org/licenses/LICENSE-2.0) four years
after each version is released. See [LICENSING.md](LICENSING.md) for a
plain-language summary. A commercial license is required to resell or host it
as a competing product, or to use the paid tier. The paid tier is not part of
this repository: it ships as separate, closed source modules under a commercial
license.

Copyright © 2026 Haruspex Systems B.V. "Ducks in a Row" is a trademark of
Haruspex Systems B.V. Haruspex Systems B.V. has its seat in Zevenaar, the
Netherlands, was incorporated on 14 August 2026, and is registered with the
Dutch Chamber of Commerce (KVK) under number 42142878.

## More

- [Documentation](docs/README.md)
- [Changelog](CHANGELOG.md)
- [Support](SUPPORT.md)
- [Security policy](SECURITY.md)
- [Contributing](CONTRIBUTING.md)

---

## Building from source

For auditors and anyone who wants to build it themselves. End users should
install from the release above.

### Toolchain

- [.NET 10 SDK](https://dotnet.microsoft.com/download/dotnet/10.0)
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
| `src/frontend` | React dashboard and setup wizard |
