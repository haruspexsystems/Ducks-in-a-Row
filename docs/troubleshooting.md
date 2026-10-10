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
discovers the CAs in Active Directory, tests the connection, checks the
service's rights on the CA, writes the configuration to `settings.json` in the
data folder, and restarts the service.

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

## The rights check shows Failed or Unproven

The wizard and the **Service rights on the CA** card on the Settings page check
what the service's own account may do. [Verifying](verifying.md#the-services-rights)
explains the five statuses. The rows that come up most:

- **Reaching the CA as this server: Failed, "the CA answered and refused".** The
  account lacks **Request Certificates** on the CA. Authenticated Users hold it
  on a default CA, so someone has taken it away. A CA that refuses remote requests
  altogether (the `IF_NOREMOTEICERTREQUEST` interface flag) answers the same way.
  The template list, the CA certificate downloads and CRL watching read through
  the same interface, so they fail too.
- **The certificate view the inventory reads: Failed.** Grant **Read** on the
  CA. Request Certificates does not open the view. If the row says the CA reports
  Read and still refused the view, the CA may refuse remote administration
  altogether (the `IF_NOREMOTEICERTADMIN` interface flag).
- **Issue and Manage Certificates: Not granted (optional).** Only revocation
  needs it. Everything else works without it; see [revocation](revocation.md)
  before granting it.
- **Issue and Manage Certificates: Unproven, "the CA would not report the
  service's roles".** The CA reports roles only to an account holding Read or
  more. Grant Read, then **Check again**.
- **Enroll on a template: Failed.** Either a deny entry refuses it, or no entry
  grants it to the account or to any group it belongs to. See
  [certificate template permissions](adcs-setup.md#certificate-template-permissions).
  A grant to a group from another domain of the forest is not visible from the
  service's server, so a row that says "no grant" can be wrong in a multi domain
  forest. The first enrolment settles it.
- **Enroll on a template: Inferred.** Not a problem. The permissions grant it,
  and nothing has enrolled from that template yet.
- **Any row: Unproven, "did not answer within N seconds".** The CA or a domain
  controller was slow or unreachable. Check again, and read the service log.

## A certificate request fails with "unknown certificate template"

The template name in the directory URL must match a template the CA publishes,
either by its programmatic name (AD `cn`) or its display name. Names are matched
case insensitively. Check the exact names in the setup wizard's template list.
Also confirm the template is published to Active Directory and the machine
account has **Enroll** on it.

The display name must not carry a control character, a Unicode line separator,
or a formatting character. See the next section if the client reports a 400
rather than a 404.

## The directory URL answers 400: the URL contains a formatting character

The client reports an error like:

```
urn:ietf:params:acme:error:malformed
The request URL contains a formatting character (U+00AD) at position 9, so it
was refused before routing.
```

**Cause.** The template's display name carries an invisible character. U+00AD
SOFT HYPHEN is the usual one: a word processor inserts them at hyphenation
points, and a display name is routinely typed by pasting. U+200B ZERO WIDTH
SPACE and the bidirectional overrides do the same thing. These characters are
invisible in the Certificate Templates console, on the dashboard, and in the
client's own configuration file alike, so the name looks correct everywhere you
would go to check it.

The server refuses any URL carrying one before routing, because such a character
can forge or disguise a line in the service log, which is the record
[hardening.md](hardening.md) tells you to read after a suspected enrollment
attack. Nothing about the template itself is wrong: it still issues normally.

**Two fixes, either one works.**

- Address the template by its **programmatic name** (its AD `cn`), which never
  carries these characters in practice. Use `/acme/WebServer/directory` rather
  than `/acme/Web Server/directory`. This needs no change on the CA.
- Retype the **Template display name** on the **General** tab of the template in
  the Certificate Templates console. Retype it rather than paste it, or the same
  character comes back. No republish is needed; the template list is re-read
  every five minutes.

**Where this is reported.** The setup wizard's template step flags the selected
template under "ACME readiness", naming the code point and the position. The
service log carries one warning near startup for any affected template that is
exposed over ACME. Neither ever prints the name itself, for the same reason the
URL is refused: writing the name would put those characters into the log.

**If the programmatic name is the one carrying it,** the template cannot be used
at all, not over ACME and not from the settings page, because Ducks in a Row
will not build an ADCS request attribute string from such a name. The setup
wizard hides such a template and counts it in its hidden templates note. A
programmatic name is fixed when a template is created, so the fix is to
duplicate the template with a clean name and publish the copy.

**If the template OID is the one carrying it, nothing is refused.** The wizard
notes it on the template's "ACME readiness" list, and the startup warning counts
it when the template is exposed over ACME, but the template issues certificates
and is addressed exactly as any other, because nothing in Ducks in a Row routes
on the OID or builds a request from it. It is reported because the wizard prints
the OID on every template row to identify the template, and the value you see
there is not the value the CA stored: the character is invisible, so the OID
looks correct on that row, in the Certificate Templates console, and anywhere
else it is shown. The row itself is safe to read. Each of the three values on it
is isolated, so a bidirectional override inside one can no longer reorder the
text around it. The OID is set when a template is created, like the programmatic
name, so there is no field to retype: either ignore the note, which costs
nothing, or duplicate the template if you would rather the row read as it is
stored.

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

## The dashboard will not let me revoke a certificate

Two independent things can stop it, and the dashboard activity feed says which.

**Cause: the capability ceiling.** A certificate is revocable from the dashboard
only when its extended key usage is present, non empty, and limited to server
authentication and client authentication, its key usage carries no certificate
or CRL signing, and it is not a CA certificate. A certificate whose capability
cannot be read at all is refused as well.

No setting raises this. It is what stops the product from being able to revoke a
domain controller certificate or the CA's own certificate, so the fix is not to
widen it. Revoke that certificate from the Certification Authority console
instead.

**Cause: the revocation scope.** Underneath the ceiling, the `revocationScope`
setting decides which certificates are in reach. The default, ducks-managed,
covers certificates Ducks in a Row obtained plus anything on a template you
enabled for ACME. If the certificate is on some other template, widen the scope
on the Settings page, or revoke it at the CA.

A `custom` scope with an empty template list disables dashboard revocation
completely. The startup log says so; check there before assuming something is
broken.

**Cause: the CA has not granted the right.** Revocation needs the server's
machine account to hold **Issue and Manage Certificates** on the CA, which is
separate from the Read that the inventory needs. The error names the missing
right. See [revocation](revocation.md).

An ACME client revoking its own certificate is not subject to the scope modes,
so a client can still revoke through `revoke-cert` when the dashboard will not.

## A device order is refused, or the device challenge never appears

`device-attest-01` fails closed, and the two refusals look different on purpose.

**Cause: no profile, or a disabled one.** A template with no device attestation
profile does not offer `device-attest-01` at all, and a device order is refused
as `unsupportedIdentifier`, exactly as if the feature did not exist. That
invisibility is deliberate: it means an install that does not use device
attestation gives nothing away about it. Create and enable a profile for the
template on the ACME page.

**Cause: the device is not on the allowlist.** This one is visible. The order is
refused with `rejectedIdentifier` and a subproblem naming the device, and the
refusal appears on the activity feed labelled as a device attestation policy
refusal. Add the device's permanent identifier to the profile's allowlist. An
empty allowlist issues to nobody.

**Cause: the attestation did not verify.** The only supported format is `apple`,
and the leaf must chain to the pinned Apple Enterprise Attestation root or to a
trust anchor you added. A custom anchor is additive and can never replace the
built in root.

**Cause: the CSR does not match.** The key in the certificate request must be
the key the attestation vouches for, with no exception and no setting. A device
CSR carrying any DNS subject alternative name is always refused.

The gate is re-checked when the order is created, when the challenge is
validated, and at finalize, so disabling a profile mid flight stops an order
that was already moving. See [device attestation](device-attestation.md).

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
  template, so the CA is holding the request for a person to approve. The
  server's own certificate is renewed on a schedule and does not wait around
  for that, so either approve the queued request in the Certification
  Authority console, or turn the setting off on the Issuance Requirements tab
  and deny the queued request. ACME issuance on that template is not stopped
  by this; see the section below for what it does instead.
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

## An ACME client waits a long time, and the order stays "processing"

The template has "CA certificate manager approval" turned on, on the Issuance
Requirements tab. Every request against such a template is held by the CA until
a person approves it in the Certification Authority console, under **Pending
Requests**. The setup wizard's readiness checklist flags this when you pick the
template, and it is a legitimate way to run a CA, so nothing stops you using it.

What happens meanwhile:

- The order sits in `processing`, which is the correct ACME status for an
  issuance the server has accepted and not yet completed.
- The service re-checks every held request once a minute. When you approve one,
  the certificate is collected and the order goes to `valid` on the next check,
  with no action from the client beyond continuing to poll.
- If you deny the request, the order goes to `invalid` and the client is told
  the CA refused it.
- If nobody decides either way before the order expires, seven days after it was
  created, the order goes to `invalid` and the log names the CA request id.
  **Approving that request afterwards issues a certificate that no longer has an
  order behind it**, so deny it instead, or revoke what it issues.

Most ACME clients give up waiting long before a person gets to the console. That
is a client timeout, not a failure of the order: the order completes regardless,
and the client collects the certificate the next time it runs. Clients that
renew on a timer handle this by themselves. If you want issuance to complete
inside a single client run, the template has to issue without approval.

To change how often held requests are re-checked, set
`Certus:Acme:PendingIssuance:PollIntervalSeconds` in `appsettings.json`. The
default is 60, and values are clamped to between 5 seconds and an hour.

## An ACME client gets "connection refused"

- The service is running: `Get-Service DucksInARow`.
- The firewall rules exist:

  ```powershell
  Get-NetFirewallRule -DisplayName "Ducks in a Row Certificate Proxy*"
  ```

- The client reaches the server on the right port (5001 for HTTPS, 5000 for
  HTTP).

## The service ignores a configuration file

The log has a Critical line saying that `settings.json` or `ducks-setup.json`
"is being ignored because it cannot be trusted". Then either the dashboard sends
you to the setup wizard, or every ACME request is refused because no template is
enabled.

The service reads these two files only when no one but SYSTEM and Administrators
could have written them:

- the file must be owned by SYSTEM or the Administrators group;
- no one else may have write access to it.

The log line says which rule the file broke. A file anyone else could change is
treated as if it were not there, because the dashboard's administrator group and
the ACME policy live in these files.

A file in this state was changed by someone other than an administrator, or its
permissions were widened by hand. **Check what it contains before you trust it
again.** Then either:

- delete it and run the setup wizard again, which writes a fresh one; or
- in an elevated PowerShell, give it back to Administrators, reset its
  permissions to the folder's, and restart the service:

```powershell
$file = "C:\ProgramData\Ducks in a Row\settings.json"
icacls $file /setowner "*S-1-5-32-544"
icacls $file /reset
Restart-Service DucksInARow
```

Saving from the setup wizard or the Settings page also replaces `settings.json`
with a fresh file. It keeps only what that page saves, so add anything else you
had in it again.

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

## The database journal mode does not match EnableWalMode

The database runs in one of two journal modes. `wal` (write ahead logging) is
the default and performs better under concurrent reads and writes, at the cost
of two sidecar files, `ducks.db-wal` and `ducks.db-shm`, sitting beside the
database while the service runs. `delete` is SQLite's plain rollback journal,
and it works on filesystems that WAL cannot use. It keeps no permanent sidecar:
a `ducks.db-journal` appears only for the moment a write is in progress and is
removed when that write commits, so seeing one briefly is normal.

`Certus:EnableWalMode` chooses between them. Journal mode is stored in the
database file rather than in configuration, so the setting and the file can
disagree. Every start reports which mode the database is actually in:

```
SQLite journal mode is delete
SQLite journal mode changed from wal to delete
SQLite journal mode is wal after a request for delete; the change was refused ...
```

Read that line rather than inferring the mode from the setting. The first form
means nothing needed doing. The second means the setting was applied. The third
means it was not.

### When the change is refused

Changing journal mode needs the database file exclusively, and the service can
only take it at startup, before it begins serving. Anything else holding the
file open at that moment refuses the change: a backup agent, an on access
scanner, a replication service, a copy of the database open in a SQLite browser,
or a second copy of Ducks in a Row pointed at the same data folder.

The service starts normally either way and retries on every start, so a refusal
is not urgent. To clear it, stop whatever holds the file and restart the
service, then confirm the logged mode.

### Moving the data folder to a network share

Do the conversion before the move, not after. A database already in `wal` mode
will not open on a filesystem that cannot support WAL, so once it is on the
share there is no start on which the service could convert it, and the service
fails to start instead:

1. With the data folder still on local disk, set `Certus:EnableWalMode` to
   `false` in `settings.json` in the data folder.
2. Restart the service and confirm the log reads
   `SQLite journal mode changed from wal to delete`.
3. Stop the service. Confirm `ducks.db-wal` and `ducks.db-shm` are gone.
4. Move the data folder to the share and update the installer's `DataDirectory`
   registry value, or set `Certus:DatabasePath` to the new location.
5. Start the service. The log should read `SQLite journal mode is delete`.

Note that WAL is a genuine performance benefit and network shares are a poor
place for a SQLite database in general. Prefer local storage for the data folder
where you have the choice.

## Cannot reach the dashboard, or get a 401

The dashboard and setup API use Windows Integrated Authentication and are
limited to the administrator group. Sign in as a member of the built in
Administrators group, or set `Auth:AdminGroup` to the Windows or Active
Directory group you want to allow, then restart the service.

## Still stuck

Ask in [GitHub Discussions](https://github.com/haruspexsystems/Ducks-in-a-Row/discussions)
or open an [issue](https://github.com/haruspexsystems/Ducks-in-a-Row/issues). For a
suspected security problem, follow [SECURITY.md](../SECURITY.md) instead.
