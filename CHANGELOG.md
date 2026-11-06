# Changelog

All notable changes to Ducks in a Row are recorded here. The format follows
[Keep a Changelog](https://keepachangelog.com/en/1.1.0/), and the project aims
to follow [Semantic Versioning](https://semver.org/spec/v2.0.0.html).

## [Unreleased]

## [1.1.0] - 2026-11-05

1.1.0 fixes vulnerabilities in 1.0.0, three rated High, so upgrade every server
soon. It also adds features: with the time and people we have, separating them
would have delayed the fixes, so this once they ship together; the next
security fix comes as a 1.1.x patch with no new features. Back up the data
folder and read [Upgrading](docs/installation.md#upgrading) first: three
database migrations run, finished orders are deleted after 90 days, a
`Certus:DatabasePath` outside the data folder stops the service, and the
fallback HTTPS certificate is replaced.

### Security

- An ACME client could get a certificate with identities or uses its order
  did not authorize, on enrollee supplies subject templates and on schema
  version 1 templates of a CA without the November 2024 update. Finalize now
  refuses, as `badCSR`, a CSR asking for anything outside a short list,
  so turn off OCSP must staple in clients. Affects 1.0.0 and earlier.
  Advisory: GHSA-gvq3-x2vf-2gg4.
- After the server was pointed at another CA, an order still waiting for a
  manager's approval at the old CA could collect an unrelated certificate from
  the new CA, then deliver it or revoke it. Such an order now fails and nothing
  is revoked. Approve or deny waiting requests before you switch, as
  [the quick start](docs/quickstart.md#2-run-the-setup-wizard) says. Affects 1.0.0.
- A database moved out of the data folder with `Certus:DatabasePath` could sit
  in a folder local users can write, beside the keys that protect the EAB
  secrets and the SMTP password. The service now refuses to start with such a
  path, so **before you upgrade**, move it back as
  [Troubleshooting](docs/troubleshooting.md#the-service-will-not-start-a-file-is-outside-the-data-folder)
  describes. Affects 1.0.0 and earlier. Advisory: GHSA-54jq-34xr-4539.
- The HTTPS endpoint offers only TLS 1.2 and 1.3, which closes a 1.0.0 Known
  Issue; a client without TLS 1.2 can no longer connect. The 1.0.0 workaround
  in `settings.json` can be removed. Affects 1.0.0 and earlier. Advisory:
  GHSA-g3f5-v9vh-97mv.
- With the allowed domain list on, an empty or unreadable list now refuses
  every order, where it allowed every name. See
  [Troubleshooting](docs/troubleshooting.md#every-acme-order-is-rejected-the-allowed-domain-list-is-empty-or-unreadable).
- An ACME client allowed to order a certificate could make the server connect
  to an address of its choosing, including one on the internal network, while
  the order was validated. That no longer happens, and nothing needs doing.
  Affects 1.0.0 and earlier. Advisory: GHSA-q76c-p53x-wxcj.
- Limits against an ACME client exhausting the server: a 64 KB request body,
  and caps on stored nonces, identifiers per order and open orders per account
  (`Certus:RateLimiting:MaxStoredNonces`, `MaxIdentifiersPerOrder` and
  `MaxPendingOrdersPerAccount`). Health reports `Degraded` on low disk
  (`Certus:FreeSpaceWarningMegabytes`). Affects 1.0.0 and earlier. Advisory:
  GHSA-h5cv-9c9x-jvg4.
- Anyone able to reach the server could stop its log file for the rest of the
  day. Affects 1.0.0 and earlier. Advisory: GHSA-6c3m-7m5r-3xqc.
- Webhook addresses, which often carry a token, no longer reach the log or the
  alert history; the log names only the host. If a 1.0.0 log was copied
  anywhere, such as a SIEM, replace the webhook URL. The fallback HTTPS
  certificate no longer uses a password shared by every install. See
  [a backup taken from 1.0.0 or earlier](docs/backup-and-restore.md#a-backup-taken-from-100-or-earlier).
  Affects 1.0.0 and earlier. Advisory: GHSA-9x26-c5j5-mp9q.
- The webhook alert for a failed renewal of the server's certificate no longer
  names the service's computer account and domain.
- The requester shown on the dashboard is checked for hidden characters, which
  closes a 1.0.0 Known Issue.
- System.Security.Cryptography.Pkcs and Microsoft.AspNetCore.Authentication.Negotiate
  moved to 10.0.13 (GHSA-846f-f764-76mx, GHSA-2fmv-rv2c-59x7,
  GHSA-vrrp-6v32-2p8g), and React Router to 7.18.4 (GHSA-2j2x-hqr9-3h42,
  GHSA-wrjc-x8rr-h8h6, GHSA-337j-9hxr-rhxg). None was reachable in 1.0.0.

### Added

- Monitor mode: a server that watches its CA and never writes to it, with the
  inventory, expiry alerts and CRL watching, and no ACME, issuance or
  revocation. Choose it in the installer (`MONITOR_ONLY=1` unattended). See
  [Monitor mode](docs/monitor-mode.md).
- An administrator audit trail on the new **Audit** page: every change made
  through the dashboard or its API, with who, when and the values before and
  after, and the refused sign ins. Nothing can switch it off. See
  [the audit trail](docs/hardening.md#the-administrator-audit-trail).
- `Auth:RequireKerberos` refuses dashboard sign ins that use NTLM. It is off by
  default; register the HTTP SPN before turning it on. See
  [NTLM and the dashboard sign in](docs/hardening.md#ntlm-and-the-dashboard-sign-in).
- Data retention: finished orders are deleted after 90 days, deactivated
  accounts after 365 and alert history after 730. The first pass runs soon
  after the upgrade, so set longer periods first if you need them. See
  [data retention](docs/configuration.md#data-retention).
- The Settings page shows the installed release's age, and after 180 days
  (`Certus:ReleaseAgeWarningDays`) says a newer release may exist. Nothing
  contacts the internet.
- A page to forward to your AD, CA and network teams, with every right and
  firewall opening the server needs. See
  [what to ask your AD and CA team](docs/ad-and-ca-team-request.md).
- The Setup Complete and Settings pages link the security notices sign up and
  the repository's advisories. The app sends nothing.
- Support for paid modules, loaded only when signed by Haruspex Systems B.V.,
  with a Licence card, a licence banner and licence alerts. None is part of
  this release, and issuance and renewal never depend on one. See
  [licence and paid module](docs/licence.md).
- The service follows its HTTPS certificate across a renewal: at startup it
  serves the newest certificate issued to the same subject from the same
  template.

### Changed

- **A fresh install requires external account binding**: the setup wizard's
  **Client Access** step starts with it ticked, so ACME clients need a
  credential to register. An upgraded install keeps its mode. See
  [enforcement modes](docs/external-account-binding.md#enforcement-modes).
- The installer sets the service to restart after a failure. See
  [If the service stops](docs/installation.md#if-the-service-stops).
- Automatic renewal renews only an HTTPS certificate the service installed
  itself (friendly name `Ducks in a Row HTTPS`). Any HTTPS certificate that
  nothing renews gets the ordinary expiry alerts.
- Setup records each template under the CA's own name, and refuses a template
  the CA does not publish.
- `SECURITY.md` says how security fixes are released. New pages cover
  [intended use](docs/intended-use.md), [upgrading](docs/installation.md#upgrading)
  and what an [uninstall](docs/uninstall.md) leaves behind.

### Removed

- `Certus:DatabasePath` outside the data folder (see Security). Choose the
  disk for the whole data folder at install instead.
- `Certus:SettingsOverlayPath` outside development, and support for a data
  folder on a network share.

### Fixed

- Saving from the dashboard no longer drops keys added to `settings.json` by
  hand. Re-add any key a 1.0.0 save removed.
- Moving an install to another CA no longer mixes up revocation records, which
  closes a 1.0.0 Known Issue.
- Saving a setting retries when another program briefly holds the setup file
  open, the cause of a 1.0.0 Known Issue.
- **Renew certificate** no longer deletes a certificate the service did not
  install.
- A CA that refuses the service account Request Certificates is reported as
  that missing right, and the ACME order stays retryable.
- An authorization becomes invalid as soon as one of its challenges fails, and
  reading a pending challenge with POST-as-GET no longer starts it.
- Account key rollover works under any template name, and one that loses a
  race answers 409 with `Location`.
- `Ducks-in-a-Row-Setup.exe` passes `INSTALLFOLDER`, `DATAFOLDER`,
  `START_SERVICE` and `MONITOR_ONLY` to the MSI.
- An alert threshold list with no positive value falls back to the defaults
  instead of sending nothing.
- The alert history says which channels delivered an expiry warning, with each
  failed channel's error.
- The setup wizard's CA search no longer hangs on a domain controller that
  stops answering.
- The **Service rights on the CA** card says how many templates it skipped, and
  a failed save on the Settings page shows the server's reason.
- The software bill of materials no longer lists packages the service does not
  install, which closes a 1.0.0 Known Issue.

### Known Issues

- **An expiry alert that fails to send is not sent again.** If the mail server
  or webhook is down when a certificate crosses a threshold, that warning is
  lost; the next threshold still fires, but an outage at the last one leaves
  none. Check the Alerts card for failed sends, and use its test send after any
  change to the mail server or webhook.
- **A flood of requests can push the oldest log files out.** Anyone able to
  reach the server can make it write enough log to roll older files away, so
  history is lost; the log is no longer silenced. Forward the log to a separate
  system as it is written if you need it. Advisory: GHSA-6c3m-7m5r-3xqc.

### Verify the download

`SHA256SUMS` lists the SHA-256 of each file, and `Ducks-in-a-Row-1.1.0.cdx.json`
is the software bill of materials. `Get-AuthenticodeSignature` should name
Haruspex Systems B.V. as the signer; see
[Check the download](docs/installation.md#check-the-download).

## [1.0.0] - 2026-10-08

The first general release. Every server running a beta should upgrade, because this release
fixes a local privilege escalation (see Security). Back up the data folder first, as
[Backup and restore](docs/backup-and-restore.md) describes.

Ducks in a Row receives security fixes until 31 December 2031, through upgrades to the latest
release. It is free for production use under the Business Source License 1.1; see
[LICENSING.md](LICENSING.md). Paid modules are separate, and none is part of 1.0.0.

### Security

- A standard local user could make themselves a dashboard administrator, because the data folder
  inherited open permissions from `C:\ProgramData`. Affects 0.9.0-beta.1 and 0.10.0-beta.1. The
  data and installation folders are now restricted to SYSTEM and Administrators, also on upgrade,
  and the service ignores a configuration file others can write. See
  [Troubleshooting](docs/troubleshooting.md#the-service-ignores-a-configuration-file).
- An ACME client could make the server connect to an internal address and port of its choosing.
  Orders now accept only host names as `dns` identifiers, and the HTTP-01 validator connects only
  to ports 80 and 443. Affects 0.9.0-beta.1 and 0.10.0-beta.1.
- Deactivating an ACME account or an authorization from the client now takes effect. Before, the
  server reported success and the account or authorization stayed usable, so an account whose key
  was retired could still place orders.
- An ACME client can no longer tell from error responses whether device attestation is enabled
  on a template that does not offer it.
- A hidden formatting character in a template's OID is now flagged, so it can no longer make the
  setup wizard's template row read as a different template.
- The alert settings API no longer returns the SMTP username, only whether one is saved. This was
  a Known Issue in 0.10.0-beta.1.

### Added

- Kubernetes and OpenShift: cert-manager's built in ACME issuer can get certificates that chain to
  your ADCS root. See [Kubernetes and OpenShift](docs/kubernetes.md).
- The setup wizard checks the service's rights on the CA before first use and says what it could
  not prove. The **Service rights on the CA** card on the Settings page checks again. See
  [the service's rights](docs/verifying.md#the-services-rights).
- Revocation lists for every CA in the chain, the offline root's included, are watched wherever
  they are published, and alerted on like certificate expiry. The **Revocation lists** card on
  the Settings page shows them. See [alerts](docs/alerts.md).
- ACME Renewal Information (RFC 9773). Clients that support it get a renewal window, and are told
  to renew at once when a certificate is revoked. New orders may name the certificate they replace.
- An order the CA holds for manager approval completes once the approval is given.
- Code signing: both installers, and every `.exe` and `.dll` the MSI installs, are signed by
  Haruspex Systems B.V. and timestamped, so one publisher rule in App Control for Business or
  AppLocker allows them. Earlier releases were not signed.
- A CycloneDX 1.6 software bill of materials ships with every release.
- The installer carries the product's branding and icon.

### Changed

- Dashboard API errors use problem types under `https://ducksinarow.dev/problems/`. A script that
  compares the full type string needs the new base. ACME error types are unchanged.
- Test Connection says why it failed: a refused account, an unreachable CA and a missing
  RSAT-ADCS-Mgmt feature each get their own message.
- ACME rate limits: a refusal names the limit and is logged. Polling has its own budget,
  `Certus:RateLimiting:PollLimit` (default 300), the window slides in
  `Certus:RateLimiting:SegmentsPerWindow` steps (default 6), and `Certus:RateLimiting:HelpUrl`
  adds a `Link` header to your own documentation.
- ACME responses: a request from a deactivated account answers 401 rather than 403; a POST to an
  authorization with a `status` the server does not act on answers 400 `malformed`; deactivating
  an authorization moves its order to `invalid`; an account's contact list is capped at 10
  entries of 255 characters.
- `PUT /api/alerts/config`: an empty or missing `username` keeps the saved one, and the new
  `clearUsername` removes it.
- Messages and log lines say Ducks in a Row. Configuration keys keep their `Certus:` prefix. The
  default alert sender is `ducks@localhost`.
- The installation guide PDF is generated from the documentation and has sixteen chapters, with
  new pages for system requirements, installation, configuration, ADCS setup, verifying, alerts,
  uninstalling, revocation, external account binding, and backup and restore.
- The service does not restart itself after a failure, by design. To add a recovery policy, see
  [If the service stops](docs/installation.md#if-the-service-stops).
- The project does not accept pull requests. Bug reports, feature requests and questions are
  welcome; [SUPPORT.md](SUPPORT.md) says where each one goes.
- `SECURITY.md` states the support period, and `LICENSING.md` says paid modules are separate,
  closed source and commercially licensed.

### Fixed

- A finalize that reaches a CA that is down answers 503 `serviceUnavailable` and leaves the order
  to be retried. A CA policy refusal answers `serverInternal` with the CA's reason, not `badCSR`.
- A client that disconnects during finalize, or an abandoned server certificate enrolment, no
  longer leaves an issued certificate with no order naming it.
- A device order whose attestation profile was disabled answers `rejectedIdentifier`, not `badCSR`.
- Template key algorithms are read from where ADCS stores them. An elliptic curve template is no
  longer reported as RSA, an `ECDH_P256` template enrolls with a warning about its Purpose
  setting, and the client commands the dashboard prints match the template's key.
- The server's own HTTPS certificate enrolls and renews against a template recorded by its
  display name.
- A template display name holding an invisible character, such as a soft hyphen, is flagged in
  the setup wizard, and the ACME refusal says which character and where. See
  [Troubleshooting](docs/troubleshooting.md#the-directory-url-answers-400-the-url-contains-a-formatting-character).
- A subject value ending in a backslash is shown under its real name.
- Setting `Certus:EnableWalMode` to `false` takes an existing database out of WAL mode, and the
  startup log reports the mode the database is really in.
- The database is checkpointed when the service stops. The 0.10.0-beta.1 Known Issue about an
  uninstall losing recent data was mistaken and is withdrawn.
- The cert-manager manifest the dashboard writes carries a `caBundle` placeholder and a sample
  Certificate whose key matches the template.
- The message logged when the CA withholds its revocation lists names the right that is missing,
  Request Certificates.
- Documentation corrections: which ACME clients read renewal information, how
  `Certus:ExternalUrl` decides the ACME URLs, and external account binding beside device
  attestation.
- A `new-order` whose `identifiers` holds a `null` answers 400, not 500.

### Known Issues

- **Moving an install to a different CA can attach revocation records to the wrong
  certificates.** After such a move, treat the CA as the record of what is revoked, or start
  again from an empty data folder.
- **The requester shown on the dashboard is not checked for hidden characters.** Where the
  requester matters, confirm it at the CA.
- **Saving a setting can fail while another program, such as an antivirus scanner, has the setup
  file open.** Nothing is damaged; save again.
- **A database moved out of the data folder with `Certus:DatabasePath` is not protected.** Where
  local users can write the folder it was moved to, they can add files the service reads. The
  default layout is not affected, and 1.1.0 refuses to start with such a path. Workaround: move
  the database back into the data folder as the advisory describes. Advisory: GHSA-54jq-34xr-4539.
- **The HTTPS endpoint accepts TLS 1.0 and 1.1 where Windows allows them.** Add
  `"Kestrel": { "Endpoints": { "Https": { "SslProtocols": ["Tls12", "Tls13"] } } }` to
  `settings.json` in the data folder and restart the service, or turn the old versions off in
  Windows' SCHANNEL settings.
- **The software bill of materials lists about fifteen design time packages that are not
  installed**, so a scanner may report findings for software that is not on the server.

### Verify the download

`SHA256SUMS` lists the SHA-256 of each file, and `Ducks-in-a-Row-1.0.0.cdx.json` is the software
bill of materials. `Get-AuthenticodeSignature` should name Haruspex Systems B.V. as the signer;
see [Check the download](docs/installation.md#check-the-download). SmartScreen may warn about a
new release while the certificate builds a reputation.

## [0.10.0-beta.1] - 2026-08-09

A beta. The installer is not code signed, so SmartScreen and Microsoft Defender
warn when you run it; check the download against `SHA256SUMS`. Verified on
Windows Server 2019 and Windows Server 2025. On Windows Server 2022, install
current Windows updates first (see Changed). Read the Known Issues before
installing.

### Added

- External account binding (RFC 8555 section 7.3.4). An administrator issues
  credentials, and enforcement is off, optional or required. A credential can
  carry an expiry, a domain namespace its accounts may order within, and a link
  to the AD account it was issued to.
- An ACME page in the dashboard, with tabs for enforcement, credentials and
  accounts. It writes ready to paste client setup for certbot, win-acme,
  acme.sh, Posh-ACME, cert-manager and Caddy, and can deactivate an account,
  which also invalidates its open orders.
- Allowed domains: restrict which DNS names ACME clients may order. A new
  install on a domain joined server starts restricted to its AD domain; an
  existing install stays unrestricted until you turn it on.
- ACME device attestation (`device-attest-01`) for Apple devices, off by
  default and gated by an allowlist. See
  [device attestation](docs/device-attestation.md).
- Automatic renewal of the server's own TLS certificate, applied with an
  announced restart from the dashboard, and a **Provision certificate** action
  on the Settings page for a server that never enrolled one.
- An Alerts card on the Settings page: whether alerting works, the thresholds,
  the recipients, recent alerts and failures, and a **Send a test** button. The
  alert settings and the whole SMTP transport are editable there, and the SMTP
  password is write only.
- A revocation scope for the dashboard: `ducks-managed` (the default),
  `custom` or `all`, each inside the TLS capability ceiling under Security.
  ACME `revoke-cert` is not affected.
- `Certus:Acme:ChallengeValidation:BlockPrivateRanges` keeps challenge
  validation away from the RFC 1918 ranges. It is off by default; see
  [hardening](docs/hardening.md).
- The certificate inventory filters by expiry state, offers a page size and a
  sortable Issued column, marks what was issued through ACME, infers
  supersession, and shows the CA's reason for a pending, denied or failed
  request and the expiry warnings sent for each certificate.
- Certificate detail offers the certificate as a download and as PEM, shows its
  thumbprint, key, signature algorithm and extended key usages, and can revoke
  it.
- Dark mode.
- A footer on every page and in the setup wizard, linking the feedback address
  and GitHub Discussions. The app itself sends nothing.

### Changed

- Built on .NET 10 LTS, and the setup file embeds the ASP.NET Core 10.0.10
  Hosting Bundle. **On Windows Server 2022, install current Windows updates
  first**: on a host not serviced since early 2022 the service cannot start,
  which the installer reports as Error 1920. The service log in
  `C:\ProgramData\Ducks in a Row\logs` holds the real error.
- `GET /api/alerts/config` no longer returns the webhook address, its header
  names or the SMTP transport settings, only the recipients and presence flags.

### Fixed

- The ACME `issuer-cert` link accepts POST-as-GET, so Caddy and Apache mod_md
  can finish issuing.
- An ACME request with the wrong method or `Content-Type` answers 405 or 415
  with a problem document rather than 404. A rate limited request carries
  `rateLimited` and `Retry-After`, and an unreachable CA answers 503 at
  `new-account` and `new-order`.
- Alert error text no longer shows configured secrets, such as a token in a
  webhook address.
- "Expiring soon" follows the configured alert thresholds everywhere.
- The email channel no longer reports itself enabled with no sender address.
- The certificate pages say when nothing has synced yet, show the CA and the
  last sync, and report a failed sync. The list shows the CA requester, and
  pending and denied requests show their names.
- A common name holding a comma, or text that looks like a hex escape, is shown
  as issued.
- Two revocations of one certificate at the same moment no longer both reach
  the CA.
- The Alerts card's restart banner clears after the restart, the setup
  wizard's Next button waits for its TLS restart, and the dashboard's fonts load
  under its content security policy.
- The Settings page shows the commit each build came from.

### Security

- A TLS capability ceiling. The dashboard revokes, and ACME delivers, only
  certificates for TLS server and client authentication, never a CA, code
  signing or domain controller certificate. No setting widens it.
- ACME finalize refuses a CSR naming anything other than DNS names in its
  subject alternative name, such as an IP address, an email address or a UPN,
  and checks every common name against the order. Before, on a template that
  takes the subject from the request, a client could get a certificate for an
  identity it had not validated.
- The enabled template policy fails closed: a missing or unreadable
  `ducks-setup.json` exposes no template over ACME, where it exposed all of
  them.
- Control and formatting characters are refused in the ADCS request, the CA
  connection string and the URL path, and stripped from stored certificate
  subjects, so they can no longer add request attributes, forge log lines or
  disguise a name.
- Microsoft.AspNetCore.Authentication.Negotiate moved to 8.0.29
  (CVE-2026-47300, CVE-2026-47303), and the bundled SQLite past
  GHSA-2m69-gcr7-jv3q.

### Known Issues

Each is fixed in a later release, except the uninstall entry, which was
withdrawn.

- **The alerts configuration API returns the SMTP username.** It needs an
  administrator session, and the password is not affected.
- **Withdrawn: uninstalling through the bundle can lose recent data.** This was
  mistaken. An uninstall keeps every committed transaction; see the 1.0.0
  notes.
- **Templates with an ECDSA key are reported as RSA**, so the wizard's own TLS
  enrolment can ask for the wrong key. ACME issuance is not affected.
- **ACME account update and deactivation take no effect.** A client told its
  account is deactivated can still order with it. Deactivate the account on
  the dashboard's ACME page, or revoke its credential, instead.
- **Two narrow character gaps.** The separators U+2028 and U+2029 pass the
  character guards, and a bidirectional override in a common name can disguise
  a certificate's download filename. Both are low severity.

## [0.9.0-beta.1] - 2026-07-13

The first public release of Ducks in a Row. It ships unsigned; a signed 1.0
follows this beta.

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
- An empty CA connection string leaves the service unconfigured: CA
  operations answer 503 until the setup wizard connects a CA.
- Same version rebuilds of the MSI now replace the installed product instead
  of installing beside it. Installing the new MSI also removes stacked
  duplicate installs from earlier builds and stops the orphaned service they
  left behind; uninstall reliably stops and removes the service again.
