# Quickstart

Get from a fresh install to your first issued certificate. Plan for about
fifteen minutes the first time, most of it spent on Active Directory
permissions.

> New to ACME or ADCS? The [glossary](glossary.md) explains the key terms.

## Before you start

You need:

- A Windows Server that is **domain joined** to the same forest as your ADCS
  certificate authority.
- The **ADCS Remote Administration Tools** installed on that server. They
  register the COM classes Ducks in a Row uses to talk to the CA:

  ```powershell
  Install-WindowsFeature RSAT-ADCS-Mgmt
  ```

- The server's **machine account** granted, on the CA:
  - **Enroll** on each certificate template you want to expose, and
  - **Read** on the CA itself (Certification Authority console, CA properties,
    Security tab). Read is what lets the dashboard sync the certificate
    inventory. Without it, enrolment still works but the dashboard stays empty.
- Optional: your CA connection string in `CAHOST\CA Name` form. The setup
  wizard discovers the CAs published in Active Directory on its own; you only
  need the string for manual entry. Find it with:

  ```powershell
  certutil -config - -ping
  ```

## 1. Install

Download from the
[latest release](https://github.com/haruspexsystems/Ducks-in-a-Row/releases) and
run it on the server. There are two downloads and you almost certainly want the
first:

- **`Ducks-in-a-Row-Setup.exe`** carries the ASP.NET Core 10 runtime inside it,
  so it installs on a server with no internet access from the one file. It skips
  the runtime install when one is already present, and never removes it on
  uninstall.
- **`Ducks-in-a-Row.msi`** is the application alone, for deployment systems that
  manage the runtime themselves. Without the runtime the service fails before it
  can log anything and the installer reports a misleading **Error 1920**.

Both installers are code signed by Haruspex Systems B.V. Check the signature and
the SHA256 checksum on the release page before you run either one, as
[checking the download](installation.md#check-the-download) describes. Windows
SmartScreen may still warn about a new release; if it does, **More info** should
name Haruspex Systems B.V. as the publisher. The install wizard lets you:

- choose the destination folder (default `C:\Program Files\Ducks in a Row\`),
- choose the data folder for the database, logs, and runtime configuration
  (default `C:\ProgramData\Ducks in a Row\`),
- choose whether to start the service immediately,
- open the setup page in your browser from the completion screen.

In all cases the installer:

- copies the application to the destination folder you chose,
- creates the data folder and records its location in the registry so the
  service finds it,
- registers the Windows service **DucksInARow** (display name "Ducks in a Row
  Certificate Proxy", runs as LocalSystem, set to start automatically on boot),
- opens inbound firewall rules on **TCP 5000** (HTTP) and **TCP 5001** (HTTPS),
- adds a **Ducks in a Row** Start Menu shortcut to the web UI.

### Unattended install

```
msiexec /i Ducks-in-a-Row.msi /qn INSTALLFOLDER="D:\Ducks in a Row" DATAFOLDER="D:\DucksData" START_SERVICE=0
```

- `INSTALLFOLDER`: destination folder (optional; defaults to
  `C:\Program Files\Ducks in a Row`).
- `DATAFOLDER`: data folder (optional; defaults to
  `C:\ProgramData\Ducks in a Row`). Choose it at install time; moving it on a
  later upgrade is not supported.
- `START_SERVICE`: `1` (default) starts the service after install; `0` registers
  it but leaves it stopped until the next boot or a manual start.

The "open the setup page" prompt only appears in the interactive wizard, so a
`/qn` install never launches a browser.

## 2. Run the setup wizard

Open the dashboard in a browser on `https://your-server:5001` (or
`http://your-server:5000`). You must sign in as a member of the administrator
group. By default that is the server's built in Administrators group; set
`Auth:AdminGroup` in `settings.json` in the data folder to delegate to a
specific Windows or Active Directory group.

> The HTTPS endpoint uses a self signed certificate out of the box (generated in
> the data folder as `ducks-selfsigned.pfx`), so your browser will warn on
> first visit. For production, give Ducks in a Row a certificate your clients
> already trust (see
> [Giving clients a TLS certificate they trust](#giving-clients-a-tls-certificate-they-trust)
> below).

Until setup completes the service is **unconfigured**: it serves the wizard and
the dashboard shell, and every CA operation answers 503. It never falls back to
a fake CA on its own.

On first run you are taken to the setup wizard. It walks you through six short
steps. It remembers where you were, so a service restart in the middle of it
does not send you back to the beginning.

![Setup wizard welcome step listing what you need before you start](images/setup-01-welcome.png)

1. **Welcome.** A short checklist of what you need before you start.
2. **Connect a CA.** The wizard discovers the CAs published in Active Directory
   and lets you pick one, or enter `CAHOST\CA Name` by hand. It then tests the
   connection through the same DCOM path the service uses in production. A pass
   proves that the service's account holds Request Certificates on the CA, and
   the wizard then checks the service's other rights. The Review step runs the
   full check, template permissions included, and says plainly what is not
   proven yet. See [the service's rights](verifying.md#the-services-rights).

   ![Setup wizard connection step showing a discovered CA and the test connection button](images/setup-02-connection.png)

3. **Choose a template.** It lists the templates that CA publishes, checks each
   one for ACME readiness, and lets you choose the template to expose. No
   template is exposed over ACME until a selection is recorded on this step:
   on a fresh install, every template's directory URL answers 403 until then.

   ![Setup wizard templates step showing the ACME readiness checklist](images/setup-03-templates.png)

4. **Allowed domains.** Choose which domains this server may issue certificates
   for. On a domain joined server the wizard arrives here with the restriction
   already on and your Active Directory domain filled in. An entry covers the
   domain and all of its subdomains, so `corp.example.com` also covers
   `web.corp.example.com`; wildcard entries are not needed and are not accepted.

   You can turn the restriction off, but leaving it on is the recommendation.
   It restricts issuance **through Ducks in a Row only**: the CA itself can
   still issue for any name through its own tools, so this complements CA side
   controls like name constraints rather than replacing them.

   ![Setup wizard allowed domains step with the restriction enabled and one domain listed](images/setup-04-domains.png)

5. **Set the external URL.** This is the address clients will use to reach the
   server. It comes prefilled with a suggestion and is checked for you. On this
   step the wizard can also enrol an HTTPS certificate for the server from your
   CA in one click, so clients trust the connection (see
   [Giving clients a TLS certificate they trust](#giving-clients-a-tls-certificate-they-trust)).

   ![Setup wizard external URL step showing the server URL and the directory URL clients will use](images/setup-05-external-url.png)

6. **Review and apply.** The step summarises your choices and runs the rights
   check again, with a row for each template you chose. Unless step 5 enrolled
   an HTTPS certificate for the server, Complete Setup waits for you to tick a
   box naming the rights that are not proven yet. It never refuses because a
   right is missing. Your choices are then saved to `settings.json` in the data
   folder and the service restarts itself to load them. The wizard waits for the
   service to come back, then shows a ready to run certbot command and opens the
   dashboard.

   ![Setup wizard review step summarising the CA, the template, the allowed domains and the external URL](images/setup-06-review.png)

To point an existing install at a different CA later, you have two options.
Either edit `Certus:CaConnectionString` in `settings.json` in the data folder
and restart the service, or clear that value and restart to reopen the wizard.
Setup locks once it is complete, so the wizard will not reopen while a CA is
still configured.

## 3. Request your first certificate

Each certificate template is its own ACME endpoint:

```
https://your-server:5001/acme/<template>/directory
```

`<template>` is the template's programmatic name (its AD `cn`) or its display
name. Display names with spaces work; the client URL encodes them. A display
name carrying an invisible character, such as a soft hyphen left behind by a
paste from a word processor, is refused with a 400; use the programmatic name
and see [Troubleshooting](troubleshooting.md).

Point any standard ACME client at that directory URL and request a certificate.
A quick test with certbot:

```bash
certbot certonly --standalone \
  --server https://your-server:5001/acme/WebServer/directory \
  --email you@example.com \
  -d host.corp.example.com \
  --key-type rsa --rsa-key-size 2048
```

> [!WARNING]
> **Match the key type to the template.** Your client must ask for the key type
> the template wants, and templates differ. An RSA template needs an RSA key; an
> `ECDSA_P256` template needs a key on that curve. Ask for the wrong one and the
> CA policy module refuses at finalize with `Denied by Policy Module`.
>
> You do not have to work this out yourself. The wizard's template step reports
> the key algorithm it read from the template, and the **Client setup** snippets
> on the dashboard's ACME page arrive with the right flags already filled in.
> Copy them from there rather than from memory.
>
> The stock `Web Server ACME` template is RSA, which is why the command above
> forces RSA: most clients default to an elliptic curve key. See
> [connecting ACME clients](acme-clients.md#key-type) for the per client flags.

Out of the box no account pre-registration is needed and no external account
binding is required: the client creates an account from its own key the first
time it connects. If an administrator has set EAB enforcement to Optional or
Required, the client needs a credential as well. See
[external account binding](external-account-binding.md).

See [Connecting ACME clients](acme-clients.md) for certbot, win-acme, Caddy,
Traefik, and Posh-ACME.

## 4. Confirm it worked

![The dashboard showing the certificate inventory and expiry tiles after the first sync](images/dashboard-overview.png)

- The client writes out the issued certificate and chain.
- The certificate appears in the dashboard inventory within one sync cycle
  (every 5 minutes by default, `Certus:SyncIntervalMinutes`).
- The health endpoint reports healthy:

  ```powershell
  Invoke-RestMethod https://your-server:5001/health
  ```

If anything misbehaves, see [Troubleshooting](troubleshooting.md).

## Configuration reference

The settings below are the ones a first install usually touches.
[Configuration](configuration.md) is the complete list, including alerting, rate
limiting, challenge egress and the keys that ship as an explicit null.

Configuration is layered. Shipped defaults live in `appsettings.json` in the
installation folder; the setup wizard writes instance settings (CA connection
string, external URL) to `settings.json` in the **data folder**, which
overrides them and survives upgrades. Environment variables override both.
Restart the service after editing either file.

| Setting | Default | Purpose |
|---|---|---|
| `Certus:CaConnectionString` | `null` (unconfigured; the wizard sets it) | ADCS CA in `CAHOST\CA Name` form |
| `Certus:DatabasePath` | `ducks.db` in the data folder | SQLite database file |
| `Certus:ExternalUrl` | `null` | The base URL you expect clients to use. Recorded and checked at startup; ACME URLs themselves follow the host the client connects to |
| `Certus:SyncIntervalMinutes` | `5` | How often the dashboard syncs from the CA |
| `Certus:RequestHistoryDays` | `30` | How far back the sync reaches for pending, denied, and failed requests, so their detail pages can show the CA's own explanation. Issued and revoked certificates are always synced in full. Set to `0` to skip those three passes entirely, which also empties the Pending, Denied, and Failed filters on the certificate list |
| `Certus:Acme:ExposeAllTemplates` | `false` | Break glass override: expose every CA published template over ACME, ignoring the wizard's template selection. Leave it `false`; the open posture is logged as a warning at startup |
| `Certus:EnableWalMode` | `true` | SQLite write ahead logging, for better concurrent read and write performance. Set it to `false` on a filesystem that cannot support WAL, or when a backup or replication tool needs a single database file with no `-wal` and `-shm` sidecars. Applied in both directions on every start, so changing it converts the existing database. See [Troubleshooting](troubleshooting.md#the-database-journal-mode-does-not-match-enablewalmode) before moving the data folder to a network share |
| `Auth:Mode` | `Negotiate` | Windows Integrated Authentication for the dashboard |
| `Auth:AdminGroup` | `null` (built in Administrators) | Group allowed into the dashboard and setup |
| `Auth:RequireHttps` | `true` | HSTS and HTTP to HTTPS redirect outside development |
| `Auth:TrustedProxies` | `[]` | Reverse proxy IPs whose `X-Forwarded-*` headers are trusted |

### Challenge validation egress

For HTTP-01 and TLS-ALPN-01, the server itself connects out to the host being
validated. Loopback, link local (including the cloud metadata address), and
IPv6 unique local targets are always refused; the RFC 1918 private ranges are
allowed by default, because an internal CA usually issues for exactly those
addresses. If everything you validate is public, set
`Certus:Acme:ChallengeValidation:BlockPrivateRanges` to `true` in
`settings.json`. The [hardening guide](hardening.md) explains the tradeoff and
the rest of the egress settings.

### Giving clients a TLS certificate they trust

ACME clients refuse to connect to an ACME server whose own TLS certificate they
do not trust. The easiest fix is built into the app: on the external URL step,
the setup wizard can enrol an HTTPS certificate for this server from the CA you
connected, install it, and reload the service to serve it. The **Settings** page
can renew that certificate later. Try these built in options first.

If you would rather supply your own certificate (for example, one from a
different issuer), point Kestrel at a PFX file instead:

```json
"Kestrel": {
  "Endpoints": {
    "Https": {
      "Url": "https://0.0.0.0:5001",
      "Certificate": {
        "Path": "C:\\ProgramData\\Ducks in a Row\\ducks.pfx",
        "Password": "your-pfx-password"
      }
    }
  }
}
```

For a quick lab test only, you can set `Auth:RequireHttps` to `false` and use
plain HTTP on port 5000 instead.

See the Alert Configuration section of the
[Installation Guide](Ducks-in-a-Row-Installation-Guide.pdf) for SMTP and webhook expiry
notifications, or the [Troubleshooting](troubleshooting.md) page for common
issues.
