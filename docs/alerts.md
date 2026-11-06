# Expiry alerts

Ducks in a Row watches every certificate in its inventory and tells you before
one expires, by email or by webhook.

## Thresholds

By default an alert fires 30, 14, 7 and 1 days before expiry. Each certificate
gets at most one alert per threshold, so a certificate does not nag you hourly
for a month. The monitor sweeps every 60 minutes.

Both are configurable: `Certus:Alerts:ThresholdDays` and
`Certus:Alerts:CheckIntervalMinutes`. See [configuration](configuration.md).

## Revocation lists

Ducks in a Row also watches the certificate revocation lists of every CA in the
chain of the connected CA, including the ones published by a CA above it.

This matters more than it sounds. A certificate expiring breaks one service. A
CRL expiring breaks revocation checking for **everything that CA ever signed**,
at once, on every client that checks revocation: domain controllers, VPN and
wireless authentication, and the certificate authority's own service. An offline
root's CRL is the dangerous one, because it expires on a schedule of its own,
nothing automatic replaces it, and the root is switched off and easy to forget.

### Where each CRL is read from

- The connected CA's own CRLs come from the CA itself, over the same connection
  everything else uses, and from the locations the CA tells its clients to read
  them.
- The CRL covering the CA's own certificate, which on a two tier estate is the
  offline root's, is read from the distribution points named on that
  certificate. Both `ldap://` and `http://` locations are read.

Every copy is checked against the certificate of the CA that should have signed
it, and one that does not verify is ignored rather than trusted.

**Each copy is watched separately, and that is the point.** A root CRL renewal
that is published to the directory but never copied to the web server leaves the
web server serving a CRL that expires, and every client that reads the HTTP
location fails while the domain looks healthy. Ducks in a Row warns about the
stale copy, names the location, and says that a newer CRL already exists
elsewhere.

### When it warns

Which rule applies depends on who replaces the CRL:

| The CRL is | What you get |
|---|---|
| Replaced by a CA on a timer (the connected CA's own, and any short lived one) | One warning when the CA misses its own scheduled publication, and one when the CRL actually expires |
| Published by hand (an offline root or policy CA, recognised by a CRL that outlives your widest threshold) | The same ladder as certificate expiry: 30, 14, 7 and 1 days by default, then one when it expires |

The ladder deliberately does not run against a CRL a CA replaces on a timer. A
Windows CA publishes a weekly CRL that is valid for about seven and a half days
and replaces it with about twelve hours to spare, so the ordinary thresholds
would fire several times a week on a CA doing exactly what it should.

A warning fires once per CRL. Publishing a new one resets the ladder, so a root
CRL renewed in good time goes quiet again on its own.

### When a CRL cannot be read

A distribution point that cannot be reached, or a CA that is down, does not
silence anything: the warnings continue against the last copy that was read, and
say when that was. An unreachable location is not evidence that the CRL behind
it was renewed.

The **Revocation lists** card on the Settings page shows every CRL being
watched, each place it is published, and what was last read from each.

### Configuration

```json
{
  "Certus:Alerts": {
    "Crl": {
      "Enabled": true,
      "CheckIntervalMinutes": 60,
      "FetchTimeoutSeconds": 15,
      "MaxCrlBytes": 33554432
    }
  }
}
```

The warning thresholds are the ones above, shared with certificate expiry: a
site that wants sixty days of notice wants it for both.

## Licence

With the paid module installed and a licence stored, Ducks in a Row also tells
you before the licence runs out, through the same email and webhook channels. A
lapse never touches a certificate: it switches paid features off, and every
licence alert ends by saying so. See [licence and paid module](licence.md).

### When it warns

The paid module decides which warning is due, and Ducks in a Row sends it.

| Warning | When | Paid features |
|---|---|---|
| Expiring | 30, 14, 7 and 1 days before the licence ends, counting only those inside the licence's warning period | On |
| Grace | When the licence ends, if it has a grace period | On until the grace period ends |
| Lapsed | When the grace period ends, or when the licence ends if it has none, as a trial does | Off |

- **Each warning is sent once per licence.** A renewed licence carries a new
  licence id, so its warnings start again from the top. Restoring the previous
  licence repeats nothing.
- **Only the warning due now is sent.** A server that was switched off at 30
  days and starts again with 10 left receives the 14 day warning, not a backlog.
- **Every configured channel receives it, in full mode and in monitor mode.**
  `Certus:Alerts:Enabled` switches the certificate checks only, and there is no
  setting that turns licence alerts off.
- **With no channel configured nothing is recorded**, so a channel you add later
  still receives the warning that is due.
- **Some licences send nothing.** A licence bound to another forest switches
  nothing on here, so it sends no warnings, and the banner says why. Neither does
  a licence the paid module cannot use, or one that has not started yet.
- **The paid module has to be running.** If it has failed or stopped responding,
  nothing is sent until it runs again, and the Licence card says so.

The check runs every 5 minutes, and the paid module looks at the licence at least
once an hour, so a warning arrives within about an hour of its moment.

An email is marked NOTICE at 30 and 14 days and WARNING after that. It is never
CRITICAL, which is kept for alerts about certificates.

A webhook payload looks like this:

```json
{
  "event": "licence.expiring",
  "timestamp": "2026-12-24T09:00:00Z",
  "licenceId": "0192a3b4-c5d6-7e8f-9a0b-1c2d3e4f5a6b",
  "tier": "standard",
  "stage": "days7",
  "validUntil": "2027-01-01T00:00:00Z",
  "graceUntil": "2027-01-31T00:00:00Z",
  "daysRemaining": 6
}
```

- `stage` is one of `days30`, `days14`, `days7`, `days1`, `expired` and
  `grace_ended`.
- `daysRemaining` counts whole days to the end of the licence, or during grace to
  the end of grace. It is left out once the licence has lapsed.
- `tier` is left out when the paid module reports something that is not a tier
  name.

The licensee's name is never part of a licence alert, in the email or in the
payload. The licence id is the reference to quote when you ask about a renewal.

## Email

The whole SMTP transport can be set from the **Alerts** card on the Settings
page: relay host, port, transport security, username and password, sender
address and name, and the recipient list. That is the recommended route. It
needs no file editing, and the password is stored encrypted in the data folder
rather than sitting in a configuration file in the clear.

The file form remains available for scripted or unattended setup:

```json
{
  "Certus:Alerts": {
    "Enabled": true,
    "CheckIntervalMinutes": 60,
    "ThresholdDays": [30, 14, 7, 1],
    "Smtp": {
      "Host": "smtp.yourdomain.local",
      "Port": 587,
      "TlsMode": "starttls",
      "Username": "ducks@yourdomain.local",
      "Password": "your-smtp-password",
      "FromAddress": "ducks@yourdomain.local",
      "FromName": "Ducks in a Row",
      "Recipients": ["admin@yourdomain.local"]
    }
  }
}
```

`TlsMode` accepts `none`, `starttls` or `implicit`. Leave it out and the port
decides: 465 means implicit TLS, anything else negotiates mandatory STARTTLS.

A null `Smtp` block means email alerts are off. That is the shipped default.

> [!IMPORTANT]
> **Saving from the dashboard changes who owns the setting.** The
> Alerts card writes into the settings file in the data folder, which outranks
> `appsettings.json`. After that, editing those keys in `appsettings.json` has
> no effect. The card lists the keys it now owns, so the situation is visible
> rather than puzzling. An environment variable or command line argument still
> outranks both, and where one is in use the card disables that field and says
> why instead of accepting an edit that could never take effect.

A password saved from the dashboard is protected with the machine's Data
Protection keyring. It never appears in any file in readable form and is never
returned by the API. Restoring the data folder onto a different machine makes
it undecryptable by design, so save it again on the new machine. See [backup
and restore](backup-and-restore.md).

## Webhooks

A webhook alert is an HTTP POST carrying a JSON payload, signed with
HMAC-SHA256 in the `X-Certus-Signature` header so the receiver can verify it
came from you.

```json
{
  "Certus:Alerts": {
    "Webhook": {
      "Url": "https://hooks.example.com/services/YOUR/WEBHOOK/URL",
      "Secret": "your-hmac-secret",
      "Headers": {
        "X-Custom-Header": "value"
      }
    }
  }
}
```

A null `Webhook` block means webhook alerts are off, which is the shipped
default.

Every alert carries an `event` name, so a receiver can route on it:

| Event | Sent when |
|---|---|
| `certificate.expiring` | One or more inventory certificates crossed a threshold |
| `crl.expiring` | A revocation list published by hand crossed a threshold |
| `crl.overdue` | A CA did not replace its own revocation list on schedule |
| `crl.expired` | A revocation list is past its next update |
| `server.certificate.renewal_failed` | Automatic renewal of this server's own certificate failed |
| `licence.expiring` | The licence reached its 30, 14, 7 or 1 day warning |
| `licence.grace` | The licence ended and its grace period began |
| `licence.lapsed` | The licence lapsed: its grace period ended, or it had none |
| `test.alert` | The test button on the Alerts card |

A CRL payload names the issuing CA, whether it is a base or a delta CRL, its
number, when it expires, and every location it is served from. When a newer CRL
is published somewhere else it carries that number too, which is what tells a
receiver that a renewal reached one location and not another.

A server certificate payload carries the outcome, the template, the days left
on the certificate the server is still serving, and the reason in `detail`.
Ducks in a Row never adds the service's computer account or its domain to that
reason, which otherwise repeats the certificate authority's own words. The alert
email does name them, because it goes to your own recipients and that is the account to
grant Enroll to; a webhook often goes to a service outside your network.

**The webhook block is deliberately not editable from the dashboard.** It is
always read from the file and never written by the Settings page. An alert
destination is a place your certificate inventory gets described to, so
changing it is a file edit and a service restart, not a form field.

## A saved change needs a restart

Alerting reads its settings once, when the service starts. A change saved on
the Settings page is stored but not in force until you restart, and the card
says so rather than pretending otherwise. It offers a restart button for
exactly this.

## Alert history

The Alerts card shows whether monitoring is on, how often it checks, the
thresholds in force, who is on the recipient list, whether a webhook is
configured, and the most recent alerts including any that failed to send. A
failed send is worth looking at: an alert that could not be delivered is
indistinguishable, from the outside, from a certificate that never needed one.
Each alert says which channels delivered it and which failed, with each failed
channel's error, so a webhook failure beside a delivered email reads as
"Partly sent". A failed alert recorded by an earlier version says only that at
least one channel failed.

The same data is available from the API at `GET /api/alerts/history` and `GET
/api/alerts/summary`.

Licence alerts are not listed on the Alerts card. The service log records each
one, with the licence id and the channels it went to.

## Testing it

The Alerts card has a test send. Use it after any change to the transport: a
relay that refuses the service's credentials will refuse them at 3am on the day
a certificate expires just as readily as it does during a test, and the test is
the cheaper way to find out.
