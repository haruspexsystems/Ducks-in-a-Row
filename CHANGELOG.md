# Changelog

All notable changes to Ducks in a Row are recorded here. The format follows
[Keep a Changelog](https://keepachangelog.com/en/1.1.0/), and the project aims
to follow [Semantic Versioning](https://semver.org/spec/v2.0.0.html).

## [Unreleased]

This section becomes the **0.9 beta**, the first public release, once testing
wraps up. It ships unsigned: Haruspex Systems B.V. is still being set up, so a
code signing certificate is not available yet. A signed 1.0 follows this beta.

### Added

- ACME server (RFC 8555) that proxies certificate enrolment to Active Directory
  Certificate Services.
- A directory per ADCS template at `/acme/{template}/directory`.
- HTTP-01, DNS-01, and TLS-ALPN-01 challenge validation.
- React dashboard showing the full certificate inventory read from the ADCS CA
  database.
- Expiry monitoring with email (SMTP) and webhook alerts.
- Guided, browser based setup wizard that discovers the CAs published in Active
  Directory, live tests the connection, applies the configuration, and restarts
  the service to load it.
- Windows Integrated Authentication on the dashboard, gated to a configured
  administrator group.
- MSI installer and Windows service for production deployment, with a data
  folder prompt (also settable unattended via `DATAFOLDER=`).
- EF Core schema migrations: existing databases upgrade in place at service
  start; databases from before migrations were introduced are adopted when
  their schema matches, otherwise startup fails with a documented reset.
- Certificate revocation tracking: a dashboard tile and filtered view for
  revoked certificates, with the revocation date and reason shown whether the
  certificate was revoked through ACME or directly on the CA console.
- One click TLS certificate enrollment for the server itself during setup,
  issued from your own CA, so the dashboard and ACME clients trust the
  connection without a manual certificate.
- The setup wizard checks each certificate template for ACME readiness and
  explains any issue, restricts the list to templates that will actually
  work, and resumes where you left off if interrupted partway through.
- Change the external URL from the dashboard Settings page any time after
  setup, without hand editing configuration files.
- Manual certificate renewal and CA certificate chain download from the
  dashboard.
- On demand inventory sync: a Refresh button, plus an automatic sync right
  after any issuance or revocation, so the dashboard catches up in seconds
  rather than waiting for the next scheduled cycle.

### Changed

- Default sync interval lowered from 15 to 5 minutes, so a certificate
  revoked directly on the CA console appears on the dashboard within about
  five minutes instead of up to sixteen.
- The Fleet Health score reads "No certificates yet" rather than a
  misleading 100% healthy before anything has been issued.
- Dashboard mascot and browser tab icon updated to the duck knight artwork.

- **Clean break rename** of everything user visible from Certus to Ducks in a
  Row: install folder `C:\Program Files\Ducks in a Row`, data folder
  `C:\ProgramData\Ducks in a Row`, Windows service `DucksInARow`, executable
  `DucksInARow.Service.exe`, database `ducks.db`, log files `ducks-*.log`,
  installer `Ducks-in-a-Row.msi`. Existing pre release installs are not
  migrated: uninstall the old product, install the new MSI, and delete the old
  `C:\ProgramData\Certus` folder when you no longer need it.
- An empty CA connection string no longer falls back to the mock CA. The
  service starts unconfigured (CA operations answer 503 until the setup wizard
  connects a CA); the mock now requires the explicit `Certus:UseMockCa=true`
  and shows a banner in the dashboard.
- Same version rebuilds of the MSI now replace the installed product instead
  of installing beside it. Installing the new MSI also removes stacked
  duplicate installs from earlier builds and stops the orphaned service they
  left behind; uninstall reliably stops and removes the service again.
