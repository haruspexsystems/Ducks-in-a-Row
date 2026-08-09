# Troubleshooting

Where to look first:

- **Logs:** `logs\ducks-*.log` in the data folder (default
  `C:\ProgramData\Ducks in a Row`; daily files, 30 day retention).
- **Windows Event Log:** Application channel, source `DucksInARow.Service`.
- **Health:** `Invoke-RestMethod https://your-server:5001/health` returns
  `Healthy`, `Degraded`, or `Unhealthy`.
- **Service:** `Get-Service DucksInARow`.

| Health result | Meaning |
|---|---|
| Healthy | Database is accessible and the CA connection works |
| Degraded | Database works but the CA is not reachable |
| Unhealthy | Database is not accessible |

## CA operations answer 503, or the dashboard sends me to the setup wizard

No CA is configured yet. The service starts unconfigured on a fresh install:
it serves the setup wizard and answers 503 for every CA operation until the
wizard connects a CA. Complete the wizard at `http://localhost:5000/setup`; it
discovers the CAs in Active Directory, tests the connection, writes the
configuration to `settings.json` in the data folder, and restarts the service.

If the wizard says setup is already complete but the dashboard still reports
the CA unavailable, check `settings.json` in the data folder for
`Certus:CaConnectionString`, then restart:

```powershell
Restart-Service DucksInARow
```

## DISP_E_MEMBERNOTFOUND (0x80020003) in the logs

The ADCS COM classes are not registered on the Ducks in a Row server. Install
the ADCS Remote Administration Tools and restart the service. This feature is
required even though this server is not the CA:

```powershell
Install-WindowsFeature RSAT-ADCS-Mgmt
Restart-Service DucksInARow
```

## Health is Degraded (CA not reachable)

- Confirm `Certus:CaConnectionString` (in `settings.json` in the data folder)
  is in `CAHOST\CA Name` form.
- Confirm the server is domain joined and can reach the CA.
- Confirm DCOM and RPC are allowed to the CA: TCP 135 plus the dynamic range
  49152 to 65535.
- Test from the Ducks in a Row server:

  ```powershell
  certutil -config "CA01.corp.example.com\Corp Issuing CA" -ping
  ```

## The dashboard is empty

- The machine account needs **Read** permission on the CA (Certification
  Authority console, CA properties, Security tab). Enrolment can work without
  it, but the inventory sync cannot read the CA database. The log reports
  "CA view access denied" in that case.
- The first sync may not have run yet. Sync runs every
  `Certus:SyncIntervalMinutes` (default 5). Restart the service to force one.

## A certificate request fails with "unknown certificate template"

The template name in the directory URL must match a template the CA publishes,
either by its programmatic name (AD `cn`) or its display name. Names are matched
case insensitively. Check the exact names in the setup wizard's template list.
Also confirm the template is published to Active Directory and the machine
account has **Enroll** on it.

## The directory URL answers 403: template "is not enabled for ACME"

The template exists on the CA but is not exposed over ACME. Exposure fails
closed: only templates enabled in the setup wizard are served. Common causes:

- **The template was not selected in the wizard.** Re-run the wizard, or check
  which template it recorded, and address that template in the directory URL.
- **The wizard has not recorded a template selection yet.** A fresh install
  exposes nothing over ACME until the wizard's template step records a choice;
  every template answers 403 before that.
- **The wizard status file is unreadable.** If `ducks-setup.json` in the data
  folder is corrupt, the service log carries an Error naming the file, and no
  templates are exposed until the file is fixed or the wizard is re-run.

Setting `Certus:Acme:ExposeAllTemplates` to `true` exposes every CA published
template regardless of the wizard's selection. That is a break glass override,
named in a startup warning; leave it off in normal operation.

## An ACME order is rejected: domain is not in the allowed domain list

The client reports an error like:

```
urn:ietf:params:acme:error:rejectedIdentifier
This server's domain policy does not allow issuance for: web.other.local.
An administrator can change the allowed domains on the Settings page.
```

The allowed domain restriction is on and the requested name falls outside
every allowed domain. On the dashboard, open **Settings, Allowed Domains**
and add the domain (subdomains of an entry are covered automatically), or
turn the restriction off. Changes apply immediately, no restart needed. Each
rejected order also appears on the dashboard activity feed as **Rejected**.

## An ACME order is rejected: outside the credential's domain namespace

The client reports an error like:

```
urn:ietf:params:acme:error:rejectedIdentifier
The external account credential 'web team' this account registered with does
not allow issuance for: other.example. An administrator can change the
credential's domain namespace on the ACME page.
```

The account is bound to an EAB credential whose domain namespace does not
cover the requested name. On the dashboard, open **ACME**, find the
credential, and use **Edit** to widen its namespace (or empty the list to
remove the restriction). Changes apply to the next order immediately. When
the Settings allowed domain list is also on, it stays the ceiling: a
namespace entry outside it does not allow issuance there. These rejections
appear on the activity feed labeled as blocked by the credential's
namespace, so they are distinguishable from allowed domain list refusals.

## Registration is refused: externalAccountRequired

```
urn:ietf:params:acme:error:externalAccountRequired
```

The enforcement mode on the ACME page is **Required** and the client tried
to register without an external account binding. Create a credential on the
ACME page (or use an existing one), hand its key id and HMAC key to the
client, and pass them with the client's EAB flags; the credential row's
**Client setup** action shows the exact command for each supported client,
and [Connecting ACME clients](acme-clients.md) lists the flags. Accounts
that registered before the mode became Required are not affected; only new
registrations need a credential.

## Registration or ordering fails with 403 unauthorized naming a credential

The message names the cause:

- **Unknown external account key identifier**: the kid was mistyped, or the
  credential was deleted from a different install than the client points at.
  Check the key id against the ACME page.
- **The credential has been revoked**: revocation is terminal and also
  suspends orders from accounts already bound to it. Create a new credential
  and re register the client with it.
- **The credential expired on ...**: extend or clear the expiry with the
  credential's **Edit** action to put it and its accounts back in use, or
  create a new credential.
- **Signature verification failed**: the client holds a stale secret, most
  often after a **Regenerate** (every old copy stops verifying the moment the
  secret rotates). Paste the current secret into the client; if it was never
  saved, regenerate again and use the new value.
- **The credential is unusable on this server**: see the next section.

## EAB secrets stopped verifying after moving or restoring the data folder

The MAC secrets are encrypted at rest with a Data Protection keyring stored
next to the database and protected by the machine's DPAPI. Restoring the
data folder onto a different machine (or reinstalling Windows) means the
keyring can no longer be decrypted, so every stored EAB secret becomes
unreadable. Verification fails closed: clients get 403 unauthorized and the
log says the stored secret could not be decrypted.

The credentials themselves survive: the key id, name, expiry, and domain
namespace are plain columns. The recovery is **Regenerate** on each
credential from the ACME page, which issues a new secret on the same key id;
hand the new secret to the client and nothing else changes. Already
registered accounts are unaffected (the secret is only used at
registration).

## An ACME client reports a TLS or certificate trust error

The HTTPS endpoint uses a self signed certificate by default
(`ducks-selfsigned.pfx` in the data folder). ACME clients reject untrusted
TLS on the ACME server. Either:

- give Ducks in a Row a certificate your clients trust (Kestrel HTTPS
  certificate in `appsettings.json`), or
- add that certificate's root to each client's trust store, or
- for a quick lab test, use the per client switch to skip the check (see
  [Connecting ACME clients](acme-clients.md)).

## The dashboard says "Server certificate renewed. Restart to apply it"

Ducks in a Row renews the certificate it serves for its own HTTPS endpoint
before it expires. The renewal deliberately does not restart the service: a
production service must not bounce itself unannounced, and every ACME client
connected at that moment would lose its connection.

So the new certificate is enrolled, installed into `LocalMachine\My`, and
recorded in the settings overlay, and the service keeps serving the previous
certificate until it restarts. Renewal runs a full window ahead of expiry, so
there is no hurry, but the notice stays until you apply it and grows more
urgent as the certificate actually in use runs down.

Apply it either way:

- press **Apply now** in the banner, or **Restart now to apply it** in the
  HTTPS certificate section of the Settings page, or
- restart the service yourself:

  ```powershell
  Restart-Service DucksInARow
  ```

The superseded certificate stays in the machine store until the restart has
happened, because removing it would delete the private key the running service
is still using. It is cleaned up automatically on the next renewal check.

## The dashboard says automatic renewal of the server certificate failed

Nothing was changed: the service is still serving its current certificate, and
the attempt is retried on the next check (daily by default). The Settings page
carries the reason the certificate authority gave. The usual ones:

- **denied** — the computer account lost Enroll permission on the template.
  Grant it on the Security tab of that template.
- **pending** — someone turned on "CA certificate manager approval" for the
  template. That also stops every ACME issuance, so turn it off on the
  Issuance Requirements tab and deny the queued request.
- **sanMismatch** — the template stopped honouring the requested subject, so
  the issued certificate no longer covers the external URL host. Set the
  Subject Name tab back to "Supply in the request". The certificate the CA
  issued was discarded rather than applied.
- **failed** — usually the CA being unreachable; see the CA connectivity
  entries above.

If email or webhook alerts are configured, one alert is sent per failed
attempt. The server's own certificate is deliberately excluded from the
ordinary 30, 14, 7, and 1 day expiry alerts, because the product renews it
itself; this failure alert is the only thing those channels say about it.

To turn automatic renewal off, or to change the window, set
`Certus:HttpsCertificateAutoRenewalEnabled` or
`Certus:HttpsCertificateRenewalWindowDays` in `appsettings.json`. The default is
on, 30 days, capped at a third of the certificate's own validity so a short
lived template does not renew on every check.

## An ACME client gets "connection refused"

- The service is running: `Get-Service DucksInARow`.
- The firewall rules exist:

  ```powershell
  Get-NetFirewallRule -DisplayName "Ducks in a Row Certificate Proxy*"
  ```

- The client reaches the server on the right port (5001 for HTTPS, 5000 for
  HTTP).

## The service will not start

- Check the log files and the Application event log.
- Validate `appsettings.json` for JSON errors (a trailing comma or missing quote
  will stop startup).
- Confirm ports 5000 and 5001 are not already in use.
- Run the executable directly from an elevated prompt to see the error:

  ```powershell
  & "C:\Program Files\Ducks in a Row\DucksInARow.Service.exe"
  ```

That last step matters more than it looks. A service that crashes before its
logger starts hides its own error: Windows reports a start timeout, which reads
like a slow service, and the event log reports a crash in `coreclr.dll`, which
reads like a product bug. Only the standalone run prints the real reason.

## The installer fails with Error 1920

The full text is "Verify that you have sufficient privileges to start system
services", and it almost never means that. The installer is already elevated.
The message appears because the service started and then exited before it could
signal Windows, so this is the same problem as the section above: read
`logs\ducks-*.log` in the data folder first.

A blank or missing log means the crash happened before the logger started.

**On Windows Server 2022 the usual cause is an outdated servicing level.** The
.NET 10 runtime requires Control-flow Enforcement Technology (CET, shadow
stacks) on Server 2022, and an installation that has not been patched since
early 2022 does not provide it. The process faults inside `coreclr.dll` with
exception code `0x80131506`, and running the executable directly prints the
actual message:

```
Fatal error. Your Windows doesn't fully support CET. Please install all
available Windows updates.
```

Build 20348.587 is confirmed too old. Check yours with `winver`. Install
current Windows updates and retry. Server 2019 predates the CET requirement and
is unaffected; Server 2025 ships with it.

The other common cause of a pre-logger crash is a blank `DatabasePath`, which
yields the connection string `Data Source=` and opens a private temporary
database per connection, so the schema migration fails on a table that cannot
exist. Check `settings.json` in the data folder.

## Database schema mismatch

The service refuses to start and the log ends with "The existing database was
created by an earlier version and its schema does not match this version".

The database predates the introduction of schema migrations and cannot be
upgraded automatically. Reset it (adjust the path if you chose a different
data folder at install time):

```powershell
Stop-Service DucksInARow
Get-ChildItem "C:\ProgramData\Ducks in a Row\ducks.db*" | Rename-Item -NewName { $_.Name + '.old' }
Start-Service DucksInARow
```

The service recreates the database at the current schema on start. The synced
certificate inventory repopulates from the CA on the next sync. ACME accounts,
orders, challenge state, and alert history are lost; ACME clients register
again automatically on their next run.

Databases created by any version that shipped with migrations upgrade in place
automatically; this reset is only ever needed for databases from before that
point.

## Cannot reach the dashboard, or get a 401

The dashboard and setup API use Windows Integrated Authentication and are
limited to the administrator group. Sign in as a member of the built in
Administrators group, or set `Auth:AdminGroup` to the Windows or Active
Directory group you want to allow, then restart the service.

## Still stuck

Ask in [GitHub Discussions](https://github.com/haruspexsystems/Ducks-in-a-Row/discussions)
or open an [issue](https://github.com/haruspexsystems/Ducks-in-a-Row/issues). For a
suspected security problem, follow [SECURITY.md](../SECURITY.md) instead.
