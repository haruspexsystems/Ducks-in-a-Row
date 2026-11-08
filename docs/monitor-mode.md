# Monitor mode

Monitor mode is Ducks in a Row with issuance switched off. The service watches
your certificate authority and never writes to it: it keeps the certificate
inventory, sends expiry alerts and watches the revocation lists, and it never
submits a certificate request and never revokes one. It is the low risk first
step onto a production CA. The CA team grants a read right, you see every
certificate the CA has issued and when each one expires, and turning issuance on
later is a rights grant, a registry value and a restart, never a reinstall.
Monitor mode is part of the free tier, on a production CA too. An installation
watches one CA; for a second issuing CA, such as one in an operational
technology zone, see [several certificate authorities](several-cas.md).

You choose it when you install. A badge on every page of the dashboard says
"Monitor mode: never issues or revokes" and links to a short summary on
ducksinarow.dev.

## What it does

- **The certificate inventory.** Every certificate the CA has issued, synced from
  the CA's database, searchable on the dashboard, with its requester, template and
  expiry.
- **Expiry alerts.** Email or a webhook before a certificate expires, at the
  thresholds you set. See [expiry alerts](alerts.md).
- **CRL watching.** A warning before a revocation list goes stale, or when the CA
  fails to publish one.
- **The Settings page**, including the service rights check, which marks every
  right only issuance or revocation needs as "Not needed in monitor mode".

## What it never does

- **It never submits a certificate request.** ACME is off: every ACME URL, and the
  ACME administration API under `/api/acme`, answers 404, and the ACME page is
  hidden.
- **It never revokes a certificate.** The revoke button is hidden, and the
  endpoint behind it refuses.
- **It never enrols its own HTTPS certificate.** It serves one already in the
  machine store, or its own self signed one. See
  [the HTTPS certificate](#the-https-certificate).
- **It never writes to Active Directory.** Neither does full mode.

The service refuses each of these at several layers, ending at its CA client,
which refuses both CA writes whoever asks. Treat that as defence in depth rather
than as the control: the rights the CA team grants are what hold, whatever the
software does. [Hardening](hardening.md#monitor-mode-least-privilege-on-a-production-ca)
explains why.

## What it needs

| Requirement | Where | Why |
|---|---|---|
| **Read** on the CA | The CA's Security tab, for this server's computer account | The certificate inventory reads the CA's database |
| **Request Certificates** on the CA | The CA's Security tab | Every read of the CA's own properties goes through it: Test Connection, the CA's certificates and CRL watching. Authenticated Users hold it on a default CA, so it is usually already in place |
| DCOM access to the CA | The CA server's Certificate Service DCOM Access group | Every call to the CA. Authenticated Users are members by default |
| The ADCS management tools on this server | `Install-WindowsFeature RSAT-ADCS-Mgmt` | The client components every CA call uses |
| Domain membership | This server | The CA authenticates this server's computer account |
| TCP 135 and the dynamic RPC range (49152 to 65535) to the CA | The network | DCOM to the CA |
| Outbound LDAP (TCP 389) to a domain controller, and HTTP (TCP 80) to the CRL distribution points | The network | CRL watching reads the lists where clients read them |

Monitor mode never needs **Enroll** on a template, and never needs **Issue and
Manage Certificates**. On most CAs Read is the only right to ask for.
[What to ask your AD and CA team](ad-and-ca-team-request.md) has the full table
and a change request ready to copy.

## Choosing it at install

In the install wizard, the **Service options** screen has a checkbox: "Monitor
only: watch the CA, never issue or revoke". It is unchecked by default.

Unattended, set `MONITOR_ONLY=1`, on the MSI or on the setup bundle:

```powershell
msiexec /i Ducks-in-a-Row.msi /qn MONITOR_ONLY=1 /l*v "C:\temp\ducks-install.log"
Ducks-in-a-Row-Setup.exe /quiet /norestart MONITOR_ONLY=1 /log "C:\temp\ducks-bundle.log"
```

The installer records the choice as the registry value `Mode`, a `REG_SZ` of
`monitor` or `full`, beside the data folder's location. The service reads it once
at startup. [Configuration](configuration.md#monitor-mode) describes the value.

- **An upgrade or a repair keeps the mode.** On an interactive upgrade the box is
  already ticked on a monitor mode server; clearing it switches the server to full
  mode. `MONITOR_ONLY=1` on an upgrade switches a full mode server to monitor mode.
  Leaving it out keeps whichever mode the server has.
- **`MONITOR_ONLY` takes the value `1` and nothing else.** Any other value stops
  setup with a message saying so.
- **A `Mode` value the service cannot use stops setup.** If someone set the value
  by hand to something other than `monitor` or `full`, or as a number
  (`REG_DWORD`), setup stops and names the value rather than overwriting it. Set it
  to `monitor` or `full`, or delete it for full mode, and run setup again. An
  uninstall always works whatever the value says.
- **Uninstalling removes the value.** Installing again without `MONITOR_ONLY=1`
  comes back in full mode. The data folder, and the setup it records, are kept.

## The setup wizard in monitor mode

The wizard has four steps instead of six: Welcome, CA Connection, External URL
and Review. There is no Templates step and no Allowed Domains step, because
nothing is issued.

- **CA Connection** names the rights monitor mode needs, and the rights check
  marks the ones it does not as "Not needed in monitor mode".
- **External URL** is the address you open the dashboard at. Once the URL is
  validated, the step offers the HTTPS certificate choice described below.
- **Review** shows the CA, the URL and an Alerts card, and completing setup
  records no template.

When setup completes, **Set up alerts** takes you straight to the alert settings.

## Alerts are the product

In monitor mode, alerts are how an expiring certificate or a stale revocation
list reaches anyone, and nothing is sent until a channel is set up:

- **Email** is configured on the Settings page, the SMTP password included, which
  is stored protected.
- **A webhook** is configured under `Certus:Alerts:Webhook` in `appsettings.json`
  or `settings.json`, and is never configurable from the dashboard.

While alerting is switched off, or neither channel can deliver, every page of the
dashboard shows a warning with a link to the alert settings. See
[expiry alerts](alerts.md).

## The HTTPS certificate

Monitor mode never requests a certificate from your CA, its own included. The
External URL step therefore offers the certificates already in this server's
machine store (`LocalMachine\My`) that the service could serve, with the ones
covering the URL's host first, and the choice to keep the self signed certificate
the service generates. A certificate is offered only when the service could use
it: valid now, issued for server authentication (or for any purpose), not a CA
certificate, and holding a private key the service can actually sign with. A
certificate for another name needs a confirmation. Choosing one restarts the
service to serve it, and choosing **Go back to the self signed certificate**
undoes an earlier choice.

The usual choice is a certificate Windows autoenrolment keeps for the server, for
example from your Computer template, or one your CA team issued for the URL.

**Following a renewal.** The service records the certificate by thumbprint, and a
renewal issues a new thumbprint. At every start, if the recorded certificate has
been archived, which is what a renewal does to the certificate it replaces, or has
expired, the service serves the newest certificate issued after it to the same
subject from the same template, provided it is valid and holds its private key.
It records the new thumbprint in `settings.json` and writes a warning in the
service log saying what it did.

Three limits:

- **The choice is made at startup.** A service that runs across the old
  certificate's expiry keeps serving it until it restarts. Windows renews well
  before expiry, so any restart between the renewal and the old certificate's
  expiry is enough.
- **It needs the old certificate in the store.** A renewal archives it, which is
  enough. If someone deleted it, there is nothing to match against, and the
  service falls back to its self signed certificate and says so in the log.
- **It needs a template.** A certificate from a public CA, or imported from a
  file, names no template, so no successor can be matched to it.

In either of the last two cases, put the new certificate's thumbprint in
`Certus:HttpsCertificateThumbprint` in `settings.json`, from an elevated session,
and restart the service. That is also how to change the certificate after setup.

## Switching to issuance

1. Ask the CA team to grant this server's computer account **Enroll** on the
   template ACME clients will use, and **Issue and Manage Certificates** on the CA
   if Ducks in a Row should revoke, the automatic revocation at finalize
   included. Request Certificates and Read are already in place.
2. From an elevated PowerShell session, set the mode to full and restart:

   ```powershell
   New-ItemProperty -Path 'HKLM:\SOFTWARE\Haruspex Systems\Ducks in a Row' -Name Mode -Value full -PropertyType String -Force
   Restart-Service DucksInARow
   ```

3. Open the dashboard. It sends you to the setup wizard, reopened at the Templates
   step with your CA already filled in. Choose the template, then the allowed
   domains, check the External URL, and complete setup. Until you do, ACME
   exposes no template and the dashboard keeps returning to the wizard.

In full mode the service renews the HTTPS certificates it enrols itself, which
carry the friendly name **Ducks in a Row HTTPS** in the machine store. A
certificate you chose in monitor mode was installed by someone else, so the
service leaves it alone: Windows autoenrolment, or whoever issued it, keeps
renewing it, and the service serves the renewed certificate from its next start,
as [following a renewal](#the-https-certificate) describes. Nothing in Ducks in
a Row renews it, so it also gets the ordinary expiry alerts. The Settings page
says which of the two installed the certificate in use.

To hand its renewal to the service instead, press **Renew certificate** in the
HTTPS certificate section of the Settings page. The service enrols a certificate
of its own from your CA and renews that one from then on. The certificate you
chose stays in the machine store.

## Switching back to monitor mode

1. Set the value back to `monitor` and restart:

   ```powershell
   New-ItemProperty -Path 'HKLM:\SOFTWARE\Haruspex Systems\Ducks in a Row' -Name Mode -Value monitor -PropertyType String -Force
   Restart-Service DucksInARow
   ```

2. Ask the CA team to remove **Enroll** and **Issue and Manage Certificates**,
   which monitor mode never uses. Removing them is what makes the switch hold
   whatever the software does.

The templates setup recorded are kept but not used. An ACME order the CA was
holding for approval at the switch stays as it is, and the first check after a
switch back to full mode finishes it.
