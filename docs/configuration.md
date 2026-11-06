# Configuration

Every setting the service reads, where to put it, and which file wins.

## Where settings live

Configuration is layered. Later sources override earlier ones:

1. `appsettings.json` in the **installation** folder. Shipped defaults. Upgrades
   replace this file, so do not edit it.
2. `appsettings.{Environment}.json`, if one is present.
3. `settings.json` in the **data** folder. This is the one to edit. The setup
   wizard writes here, and it survives upgrades.
4. Environment variables.
5. Command line arguments.

Restart the service after editing a file. The overlay is not watched for
changes, and the restart is the apply step.

> **Edit `settings.json` as an administrator.** The data folder is writable only
> by SYSTEM and Administrators, so open the file from an elevated session. The
> service ignores the file, with a Critical line in the log, if anyone other
> than SYSTEM or Administrators owns it or may write it. See
> [Troubleshooting](troubleshooting.md#the-service-ignores-a-configuration-file).

> **Keep secrets out of `appsettings.json`.** The installation folder is
> readable by every local user, so an SMTP password, a webhook signing secret
> or a webhook header put there is readable by every local user too; a secret
> belongs in the dashboard, which stores it protected, or in `settings.json`
> in the data folder, which only SYSTEM and Administrators can read.

> **The service writes to `settings.json` too, and keeps your keys.** The setup
> wizard, the Settings page, the alert settings card and the HTTPS certificate
> renewal each change only the keys they manage and write every other key back
> as it was. One thing they refuse: if you set a key they manage in the colon
> form at the top level, such as `"Certus:ExternalUrl"`, a save would set
> that key twice, which stops the service starting. The save is refused
> instead and the log names the key. Move it into the `"Certus"` section and
> save again.

> **Not everything lives in these files.** The allowed domain list, the EAB
> enforcement mode, the revocation scope and the device attestation settings are
> stored separately and apply immediately, with no restart. Those are called out
> where they appear below. The instance mode lives in the registry instead; see
> [Monitor mode](#monitor-mode).

A minimal `settings.json` after setup looks like this:

```json
{
  "Certus": {
    "CaConnectionString": "CA-SERVER\\MyCA",
    "ExternalUrl": "https://ducks.yourdomain.local:5001"
  }
}
```

> [!WARNING]
> **A setting that looks like it has a default may be null.** Several keys ship
> in `appsettings.json` as an explicit JSON `null`, and the configuration binder
> applies that null over the value the code would otherwise start from. So the
> shipped file, not the code, decides the starting value for those keys. They
> are marked below.

## Core settings

| Setting | Default | Purpose |
|---|---|---|
| `Certus:CaConnectionString` | `null`, ships null | The CA, in `CAHOST\CA Name` form. The wizard sets it |
| `Certus:DatabasePath` | `ducks.db` in the data folder, ships null | The SQLite database file. It must be in the data folder, and the service refuses to start otherwise ([why](troubleshooting.md#the-service-will-not-start-a-file-is-outside-the-data-folder)); to keep the data on another disk, move the whole data folder. A blank value opens a private temporary database per connection, which is why it is normalised after binding rather than trusted from the file |
| `Certus:ExternalUrl` | `null`, ships null | The base URL you expect clients to use. Recorded and checked at startup. When it is set, every URL the ACME server hands out takes its scheme, host and port from it, whatever host the client connected to; when it is not, ACME URLs follow the host the client connects to |
| `Certus:SyncIntervalMinutes` | `5` | How often the dashboard syncs certificates from the CA. Values below 1 are raised to 1 |
| `Certus:RequestHistoryDays` | `30` | How far back the sync reaches for pending, denied and failed requests, so their detail pages can show the CA's own explanation. Issued and revoked certificates are always synced in full. `0` skips those three passes and empties the matching filters |
| `Certus:FreeSpaceWarningMegabytes` | `1024` | Below this much free space on the volume holding the data folder, the health endpoint reports `Degraded` and the log carries a warning (once when it drops, then daily while it stays low). Nothing is deleted automatically. `0` turns the check off. Absent from `appsettings.json`, so this is the default unless you add it |
| `Certus:EnableWalMode` | `true` | SQLite write ahead logging. Set `false` on a filesystem that cannot support WAL, or when a backup tool needs a single file with no `-wal` and `-shm` sidecars. Applied in both directions on every start, so changing it converts the existing database |
| `Certus:UseMockCa` | `false` | Development only. The service refuses to start if this is true while a CA connection string is set |
| `Certus:SettingsOverlayPath` | `settings.json` in the data folder | Development and tests only. The service reads the overlay from the data folder and refuses to start when this names any other file ([why](troubleshooting.md#the-service-will-not-start-a-file-is-outside-the-data-folder)) |

## The server's own HTTPS certificate

Ducks in a Row can enrol and renew its own TLS certificate from the CA it is
connected to. See [quickstart](quickstart.md) for turning it on.

| Setting | Default | Purpose |
|---|---|---|
| `Certus:HttpsCertificateThumbprint` | `null` | The certificate currently served, from `LocalMachine\My`. The wizard and the Settings page write it. When the certificate it names has been archived by a renewal, or has expired, the service serves the newest one issued after it to the same subject from the same template, and records that one here; see [following a renewal](monitor-mode.md#the-https-certificate) |
| `Certus:HttpsCertificateAutoRenewalEnabled` | `true` | Renew before expiry without being asked. Only a certificate the service installed itself is renewed, which is one carrying the friendly name `Ducks in a Row HTTPS`; a certificate someone else installed, such as one chosen in monitor mode, is left to whoever issued it. While it is on, a certificate it renews is left out of the expiry alerts, because renewal owns it; while it is off, or for a certificate it leaves alone, the server's certificate gets the same alerts as every other certificate. Monitor mode turns it off |
| `Certus:HttpsCertificateRenewalWindowDays` | `30` | How long before expiry to renew |
| `Certus:HttpsCertificateRenewalCheckIntervalHours` | `24` | How often to check |

The last three are deliberately absent from `appsettings.json`, so they take the
values above unless you add them.

## Monitor mode

Monitor mode is for a CA you want watched but not written to. The service keeps
the certificate inventory, the expiry alerts, CRL watching and the alert
settings, and turns off everything that writes to the CA: ACME, issuance and
revocation. It is the low risk first step onto a production CA. Turning issuance
on later is a rights grant, a change to this value and a restart, never a
reinstall. [Monitor mode](monitor-mode.md) has the whole picture: what it does and
never does, what it needs from the CA team, choosing it at install, the setup
wizard, the HTTPS certificate, and switching in both directions.

The installer writes the value, from the **Monitor only** checkbox or
`MONITOR_ONLY=1`. The mode is not in any configuration file. It is a registry
value beside the data folder's:

| Key | Value | Type | Contents |
|---|---|---|---|
| `HKLM\SOFTWARE\Haruspex Systems\Ducks in a Row` | `Mode` | `REG_SZ` | `monitor` or `full` |

- Absent or empty means full, so an installation that never chose behaves
  exactly as before.
- Case and surrounding spaces do not matter.
- Any other value, or a value of another type such as `REG_DWORD`, stops the
  service at startup with the reason in the log. It is never guessed at:
  reading a mistyped `monitr` as full would turn issuance back on for a CA
  whose team was promised none.
- Only a local administrator can change it, and a restart applies it. Neither
  `appsettings.json`, `settings.json`, an environment variable nor the
  dashboard can set it, by design. The one exception is a host run in the
  Development environment, which a production service never is: there
  `Certus:Development:Mode` overrides the value, for testing.

To set it, from an elevated PowerShell session:

```powershell
New-ItemProperty -Path 'HKLM:\SOFTWARE\Haruspex Systems\Ducks in a Row' -Name Mode -Value monitor -PropertyType String -Force
Restart-Service DucksInARow
```

What changes in monitor mode, in configuration terms:

- Every ACME URL answers 404, and so does the ACME administration API under
  `/api/acme`.
- The challenge validation worker, the worker that collects certificates the
  CA held for approval, and the automatic renewal of the server's own HTTPS
  certificate do not run, whatever
  `Certus:HttpsCertificateAutoRenewalEnabled` says.
- The dashboard refuses to revoke a certificate, and to enrol or renew its own
  HTTPS certificate, with the problem type
  `https://ducksinarow.dev/problems/monitor-mode`.
- The server's own HTTPS certificate gets the ordinary expiry alerts, because
  nothing renews it.
- `Certus:Acme:ExposeAllTemplates` and a revocation scope of `all` have no
  effect, and the startup log says so at Information rather than warning.

Monitor mode needs **Read** on the CA, plus the **Request Certificates** that
Authenticated Users hold on a default CA. See
[what it needs](monitor-mode.md#what-it-needs).

## ACME

| Setting | Default | Purpose |
|---|---|---|
| `Certus:Acme:ExposeAllTemplates` | `false` | Break glass. Exposes every template the CA publishes, ignoring the wizard's selection. Leave it false; the open posture is logged as a warning at every start |

Which templates are exposed is otherwise decided by the wizard and stored in
`ducks-setup.json`. With no recorded selection nothing is exposed at all, which
is deliberate: it fails closed.

`Certus:Acme:ExposeAllTemplates` does not widen what the dashboard may revoke.
That is a separate setting; see [revocation](revocation.md).

### Challenge validation egress

The server connects out to the name being validated for HTTP-01 and
TLS-ALPN-01. `device-attest-01` never connects out at all.

| Setting | Default | Purpose |
|---|---|---|
| `...ChallengeValidation:BlockPrivateRanges` | `false` | The RFC 1918 ranges are allowed, because an internal CA usually issues for exactly those addresses. Set true if everything you validate is public |
| `...ChallengeValidation:BlockLoopback` | `true` | Always refuse loopback |
| `...ChallengeValidation:BlockLinkLocal` | `true` | Always refuse link local, including the cloud metadata address |
| `...ChallengeValidation:BlockUniqueLocalIpv6` | `true` | Always refuse IPv6 unique local |
| `...ChallengeValidation:AdditionalBlockedCidrs` | `[]` | Extra ranges to refuse |
| `...ChallengeValidation:AllowRedirects` | `false` | Follow redirects during HTTP-01 |
| `...ChallengeValidation:MaxValidationAttempts` | `5` | Attempts before a challenge fails |
| `...ChallengeValidation:PollIntervalSeconds` | `5` | How often the validation worker sweeps |

The prefix is `Certus:Acme:ChallengeValidation:`. The
[hardening guide](hardening.md) explains the tradeoffs.

### Orders the CA holds

| Setting | Default | Purpose |
|---|---|---|
| `Certus:Acme:PendingIssuance:PollIntervalSeconds` | `60` | How often to ask the CA about orders it is holding for manager approval. Clamped between 5 seconds and 1 hour |

A template set to hold every request for approval is an ordinary ADCS
configuration, not an error. The order stays `processing` until an operator
approves or denies it at the CA, and this sweep is what finishes it.

### Rate limiting

| Setting | Default | Purpose |
|---|---|---|
| `Certus:RateLimiting:Enabled` | `true` | |
| `Certus:RateLimiting:NewAccountLimit` | `10` | Per window, `acme-new-account` |
| `Certus:RateLimiting:NewOrderLimit` | `30` | Per window, `acme-new-order` |
| `Certus:RateLimiting:PollLimit` | `300` | Per window, `acme-poll`: authorization and order polling |
| `Certus:RateLimiting:GeneralLimit` | `100` | Per window, `acme-general`: everything else |
| `Certus:RateLimiting:WindowSeconds` | `60` | |
| `Certus:RateLimiting:SegmentsPerWindow` | `6` | How many steps the window releases permits in |
| `Certus:RateLimiting:HelpUrl` | none | Documentation URL for a `Link: rel="help"` on a refusal |
| `Certus:RateLimiting:MaxStoredNonces` | `10000` | The most replay nonces kept at once; the oldest are evicted when it is full. Values below 1 are raised to 1 |
| `Certus:RateLimiting:MaxIdentifiersPerOrder` | `100` | The most identifiers one new-order request may name. More is refused as `malformed` |
| `Certus:RateLimiting:MaxPendingOrdersPerAccount` | `1000` | The most orders one account may hold open (pending or ready, not expired). A request from an account at the cap is refused as `rateLimited` |

A non positive value while rate limiting is enabled is logged as a warning at
startup.

The last three bound what the server stores rather than how often it is asked,
so they apply whether or not `Enabled` is on. A nonce is stored on every ACME
protocol response and lives an hour, so without the cap a client could grow the
store at line rate; evicting the oldest costs a legitimate client at most one
`badNonce` retry, which RFC 8555 requires every client to handle. No nonce is
minted on a rate limit refusal or on an unknown ACME URL. The open order cap
clears when the client finalizes an order, deactivates its authorizations, or
lets it expire a week after it was placed, so that refusal carries no
`Retry-After`.

### Which rate limit refused a request

A refusal names the policy that produced it, so you can tell which of the four
settings above to change. The name appears in three places:

- the `detail` of the ACME problem document the client receives, for example
  `Too many new account requests.`, which is what shows up in the client's output
- a `Retry-After` header, in whole seconds
- a Warning in the service log naming the policy, the path, the caller's address,
  and the setting to raise. That line is written at most once per policy per
  minute, and reports how many further refusals it did not log, so that a flood
  cannot fill the log file

Set `HelpUrl` to your own runbook to add an RFC 8555 section 6.6 `Link` header
pointing at it, with the policy name as the fragment. Nothing is sent anywhere by
default.

### The ACME polling budget

`PollLimit` covers the two POST-as-GET endpoints a client repeats while it waits,
`authz` and `order`. Their request count is set by how long validation takes
rather than by how many certificates were asked for.

The default is 5 requests a second. A client polling once a second contributes
60 a minute for as long as it waits, so the default carries about five
concurrent issuances polling that hard, or ten polling every two seconds. The
two endpoints share the budget without doubling the cost, because RFC 8555 puts
them in sequence: a client polls the authorization until the challenge settles,
then the order after finalize. Raise `PollLimit` before raising `GeneralLimit`
if clients are refused part way through an issuance; the refusal names which of
the two it was.

### Rate limits partition per source address

Every policy counts per caller address, so anything that makes many clients share
one apparent address makes them share one budget. A reverse proxy, a NAT gateway,
or a Kubernetes cluster egressing through one address will do this.

Behind a proxy, set `Auth:TrustedProxies` to the proxy's address. Until you do,
forwarded headers are ignored entirely and every client counts as the proxy, so
one fleet shares a single limit. The service says so at startup when
`TrustedProxies` is empty.

The partition is the full address, for IPv6 as for IPv4. An IPv6 client that
holds a whole /64 can therefore present a fresh address per request and sit in
a fresh partition each time; the per address limits do not stop that, and the
resource caps above (the nonce store, the identifiers per order, the open
orders per account) are what bound it. Partitioning IPv6 callers by prefix is
not implemented.

Permits are released in `SegmentsPerWindow` steps across the window rather than
all at once, so a refused fleet recovers gradually instead of retrying in
lockstep. `Retry-After` reports one step, `WindowSeconds / SegmentsPerWindow`.
A caller that spends its whole budget in a single instant still waits a full
window, and will be told to retry sooner than that; retrying early costs one more
refusal carrying a fresh `Retry-After`, which is the cheaper error than holding
back a caller that could already proceed.

Refusals are immediate. Requests are never queued, because queueing on a window
this long would hold a connection open until the window replenished instead of
answering, which is worse for the client and for the server than an immediate
refusal the client can act on.

## Alerts

See [alerts](alerts.md) for what these do. Note the shipped `appsettings.json`
writes this section with its full name as a single key, `"Certus:Alerts"`,
rather than nesting `Alerts` inside `Certus`. Both forms bind.

| Setting | Default | Purpose |
|---|---|---|
| `Certus:Alerts:Enabled` | `true` | |
| `Certus:Alerts:CheckIntervalMinutes` | `60` | |
| `Certus:Alerts:ThresholdDays` | `[30, 14, 7, 1]` | Days before expiry to alert |
| `Certus:Alerts:Smtp` | `null`, ships null | Null means email alerts are off |
| `Certus:Alerts:Webhook` | `null`, ships null | Null means webhook alerts are off |
| `Certus:Alerts:Crl:Enabled` | `true` | Watch the revocation lists of the CAs in the chain |
| `Certus:Alerts:Crl:CheckIntervalMinutes` | `60` | |
| `Certus:Alerts:Crl:FetchTimeoutSeconds` | `15` | How long to wait for a distribution point |
| `Certus:Alerts:Crl:MaxCrlBytes` | `33554432` | The largest CRL to accept, 32 MB |

Most of the SMTP block is editable from the Settings page. The webhook block is
deliberately not, so a dashboard administrator cannot redirect alert traffic.

## Data retention

How long each class of record stays in the database before the daily
retention pass removes it. The [backup and restore](backup-and-restore.md#what-the-database-keeps-and-for-how-long)
page says what each class holds and which of it is personal data. Each period
is a number of days, `0` keeps that class for ever, and none of the keys is in
`appsettings.json`, so these are the defaults unless you add them to
`settings.json`. The pass reads them at startup; restart after a change.

| Setting | Default | Purpose |
|---|---|---|
| `Certus:Retention:FinishedOrderDays` | `90` | How long after an ACME order reached `valid` or `invalid` its authorizations and challenges are kept, and how long an invalid order itself is kept. A valid order's row and its certificate record are kept until this many days after the certificate expired, because renewal information, `replaces` and ACME revocation look a live certificate up through them |
| `Certus:Retention:DeactivatedAccountDays` | `365` | How long after deactivation an ACME account keeps its contact addresses. The account row itself is deleted once that period has passed and the order rule has removed its last order |
| `Certus:Retention:AlertHistoryDays` | `730` | How long certificate, CRL and licence alert history rows are kept after the alert was sent |
| `Certus:Retention:AuditTrailDays` | `730` | How long the administrator audit trail and the refused sign in counts are kept. Never below 90: a lower value is raised to 90 and the service log says so at startup. `0` keeps the trail for ever |

The CA inventory mirror is not subject to retention and has no setting: it
reflects what the CA holds, and the next sync would recreate anything removed.
The policy rejection table keeps its newest 1,000 rows, which is not
configurable.

## Authentication

The dashboard and the setup API use Windows Integrated Authentication and are
limited to an administrator group.

| Setting | Default | Purpose |
|---|---|---|
| `Auth:Mode` | `Negotiate` | The only other legal value is `Disabled`, which the service refuses to start with while a CA is configured |
| `Auth:AdminGroup` | `null`, ships null | The group allowed in. Null means the built in Administrators group |
| `Auth:RequireHttps` | `true` | HSTS and an HTTP to HTTPS redirect outside development |
| `Auth:TrustedProxies` | `[]` | Reverse proxy addresses whose `X-Forwarded-*` headers are trusted |
| `Auth:RequireKerberos` | `false` | Refuse a dashboard sign in that used NTLM with a 401 that says why. The package every sign in used is logged whether this is on or off. Register the HTTP service principal name first; see [NTLM and the dashboard](hardening.md#ntlm-and-the-dashboard-sign-in) |

## Web server and logging

| Setting | Default | Purpose |
|---|---|---|
| `Kestrel:Endpoints:Http:Url` | `http://0.0.0.0:5000` | |
| `Kestrel:Endpoints:Https:Url` | `https://0.0.0.0:5001` | |
| `Kestrel:Endpoints:Https:Certificate:Path` | empty | Empty means the self signed certificate in the data folder is served |
| `Kestrel:Endpoints:Https:SslProtocols` | not set | Not set means TLS 1.2 and TLS 1.3 only, whatever Windows allows. A list here, such as `["Tls13"]`, replaces that. `Kestrel:EndpointDefaults:SslProtocols` is ignored for this endpoint. Every start logs the protocols the endpoint serves, and logs a warning when this list admits anything older than TLS 1.2 |
| `Serilog:MinimumLevel:Default` | `Information` | Logs go to `logs\ducks-<date>.log` in the data folder; a file rolls at 100 MB and 30 files are retained |

## What the service refuses to start with

Two combinations are refused outright, because each one silently disables a
security control that the presence of a CA says you wanted:

- `Auth:Mode=Disabled` while `Certus:CaConnectionString` is set.
- `Certus:UseMockCa=true` while `Certus:CaConnectionString` is set.

So is a `Mode` registry value that is neither `monitor` nor `full`, rather
than guessed at; see [Monitor mode](#monitor-mode).

Everything else that looks wrong is logged as a startup warning and the service
runs. Read `logs\ducks-<date>.log` after a configuration change; the warnings
name the setting.
