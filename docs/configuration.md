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

> **Not everything lives in these files.** The allowed domain list, the EAB
> enforcement mode, the revocation scope and the device attestation settings are
> stored separately and apply immediately, with no restart. Those are called out
> where they appear below.

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
| `Certus:DatabasePath` | `ducks.db` in the data folder, ships null | The SQLite database file. A blank value opens a private temporary database per connection, which is why it is normalised after binding rather than trusted from the file |
| `Certus:ExternalUrl` | `null`, ships null | The base URL you expect clients to use. Recorded and checked at startup. When it is set, every URL the ACME server hands out takes its scheme, host and port from it, whatever host the client connected to; when it is not, ACME URLs follow the host the client connects to |
| `Certus:SyncIntervalMinutes` | `5` | How often the dashboard syncs certificates from the CA. Values below 1 are raised to 1 |
| `Certus:RequestHistoryDays` | `30` | How far back the sync reaches for pending, denied and failed requests, so their detail pages can show the CA's own explanation. Issued and revoked certificates are always synced in full. `0` skips those three passes and empties the matching filters |
| `Certus:EnableWalMode` | `true` | SQLite write ahead logging. Set `false` on a filesystem that cannot support WAL, or when a backup tool needs a single file with no `-wal` and `-shm` sidecars. Applied in both directions on every start, so changing it converts the existing database |
| `Certus:UseMockCa` | `false` | Development only. The service refuses to start if this is true while a CA connection string is set |
| `Certus:SettingsOverlayPath` | `settings.json` in the data folder | Where the overlay above is read from |

## The server's own HTTPS certificate

Ducks in a Row can enrol and renew its own TLS certificate from the CA it is
connected to. See [quickstart](quickstart.md) for turning it on.

| Setting | Default | Purpose |
|---|---|---|
| `Certus:HttpsCertificateThumbprint` | `null` | The certificate currently served. The wizard and the Settings page write it |
| `Certus:HttpsCertificateAutoRenewalEnabled` | `true` | Renew before expiry without being asked |
| `Certus:HttpsCertificateRenewalWindowDays` | `30` | How long before expiry to renew |
| `Certus:HttpsCertificateRenewalCheckIntervalHours` | `24` | How often to check |

The last three are deliberately absent from `appsettings.json`, so they take the
values above unless you add them.

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

A non positive value while rate limiting is enabled is logged as a warning at
startup.

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

## Authentication

The dashboard and the setup API use Windows Integrated Authentication and are
limited to an administrator group.

| Setting | Default | Purpose |
|---|---|---|
| `Auth:Mode` | `Negotiate` | The only other legal value is `Disabled`, which the service refuses to start with while a CA is configured |
| `Auth:AdminGroup` | `null`, ships null | The group allowed in. Null means the built in Administrators group |
| `Auth:RequireHttps` | `true` | HSTS and an HTTP to HTTPS redirect outside development |
| `Auth:TrustedProxies` | `[]` | Reverse proxy addresses whose `X-Forwarded-*` headers are trusted |

## Web server and logging

| Setting | Default | Purpose |
|---|---|---|
| `Kestrel:Endpoints:Http:Url` | `http://0.0.0.0:5000` | |
| `Kestrel:Endpoints:Https:Url` | `https://0.0.0.0:5001` | |
| `Kestrel:Endpoints:Https:Certificate:Path` | empty | Empty means the self signed certificate in the data folder is served |
| `Serilog:MinimumLevel:Default` | `Information` | Logs go to `logs\ducks-<date>.log` in the data folder, 30 daily files retained |

## What the service refuses to start with

Two combinations are refused outright, because each one silently disables a
security control that the presence of a CA says you wanted:

- `Auth:Mode=Disabled` while `Certus:CaConnectionString` is set.
- `Certus:UseMockCa=true` while `Certus:CaConnectionString` is set.

Everything else that looks wrong is logged as a startup warning and the service
runs. Read `logs\ducks-<date>.log` after a configuration change; the warnings
name the setting.
