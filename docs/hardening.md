# Hardening

Ducks in a Row ships with defaults that favour first issuance on an internal
network. This page collects the optional lockdowns and explains the reasoning
behind each default, so an open posture is an informed choice rather than an
accident.

## The data folder

The installer restricts the data folder, `C:\ProgramData\Ducks in a Row` by
default, to SYSTEM and Administrators, and lets Users only read and run the
installation folder. Keep it that way. Whoever can write `settings.json` can
name the group the dashboard admits, and whoever can write `ducks-setup.json`
sets the ACME policy. The service refuses either file if anyone else may write
it, which is a backstop, not a reason to widen the folder.

The lock also protects what has no such backstop: the database, which holds
the ACME accounts, orders and EAB credentials, and the `keys` folder, which
protects the EAB secrets and the saved SMTP password. That is why the database
must stay in the data folder. The service refuses to start when
`Certus:DatabasePath` points anywhere else, and re-applies the lock to the data
folder on every start. To keep the data on another disk, choose that disk for
the whole data folder at install.

## The service account

The service runs as LocalSystem, which the CA and the directory see as the
server's own computer account. A virtual service account
(`NT SERVICE\DucksInARow`) would present the same computer account on the
network and hold far fewer rights on the server, so it was evaluated on a test
lab for release 1.1. It was not adopted:

- The Data Protection keyring is protected with DPAPI under the account the
  service runs as. Under another account the existing keys cannot be read, so
  every stored EAB secret and the saved SMTP password are lost on an upgrade
  unless the keyring is migrated.
- Renewing the server's HTTPS certificate writes to the machine's personal
  certificate store and restarts the service, and neither is open to a virtual
  account without widening the store's permissions and the service's own.
- The CA rights an attacker would inherit are the computer account's either
  way. What limits them is granting that account only the rights you need, as
  [the CA rights](#monitor-mode-least-privilege-on-a-production-ca) below
  describe.

Do not change the account the service logs on as, in Services or with
`sc.exe config`. Measured on that lab: the service stops starting and writes
nothing to its log, because it can no longer apply the data folder's
permissions; with those widened by hand, the stored EAB secrets can no longer
be decrypted, HTTPS on port 5001 drops every connection when it serves a
certificate from the machine store, until that certificate's private key admits
the new account, and a certificate renewal fails after the CA has already
issued the certificate. Changing back to LocalSystem does not undo it either.
Every file the other account wrote is owned by that account, so the service
then refuses a `settings.json` or `ducks-setup.json` written in between and
runs as if it were absent, and any secret saved in between cannot be decrypted.
That direction was not measured.

What limits a compromise of the service instead: the locked data and
installation folders above, the publisher check on a paid module before it is
loaded, the [administrator audit trail](#the-administrator-audit-trail), and
[monitor mode](monitor-mode.md) on a CA you do not yet want it to write to.

## The administrator audit trail

Every change an administrator makes through the dashboard or its API is
recorded: who made it, when, what it touched, and where a setting changed, the
value before and after. The Audit page shows the trail, newest first, with a
filter by administrator. The record is the Windows identity the dashboard
authenticated, so it is only as good as the sign in: keep the dashboard on
Windows Integrated Authentication and the admin group small, and read
[NTLM and the dashboard sign in](#ntlm-and-the-dashboard-sign-in) below.

Three things make the trail hard to silence. It has no setting that turns it
off. Nothing an administrator can reach from the dashboard edits or deletes a
row; the only thing that removes one is the daily retention pass, whose period
is `Certus:Retention:AuditTrailDays` (two years by default, and a value below 90
days is raised to 90, so a short period cannot be used to hide a change). And
every row is also written to the service log at Warning level, which a raised
minimum level cannot drop, so the log file and the database are two records of
the same action.

A change to a settings file is recorded before the file is written. If the
write is then refused, a second row says so, so a change that did not land is
never mistaken for one that did. A change to the database, such as erasing an
account or revoking a credential, is recorded in the same transaction as the
change, so the row and the change commit or roll back together.

The trail never carries a secret. A credential's MAC secret, an SMTP password
and a licence file's bytes are described by what happened to them (created,
regenerated, cleared) and never by their value.

The same page counts refused sign ins: requests to the API that offered
credentials and were refused (401), and requests from a signed in account that
is not in the admin group (403), per source address and per hour, so a
password guessing attempt against the dashboard shows as a growing count
against one address. A browser's first unauthenticated request, which is how
Windows authentication always starts, is not counted, and nor is an
administrator's own request that lacked the anti forgery header. The counts
are kept for the same period as the trail.

## NTLM and the dashboard sign in

The dashboard signs administrators in with Windows Integrated Authentication
(Negotiate), which settles on Kerberos when it can and falls back to NTLM when
it cannot. The two are not equal. A Kerberos ticket is issued for the name of
the server the browser asked for and is useless to any other host. An NTLM
exchange is not tied to a host at all, so an attacker who can get an
administrator's browser to authenticate to them can relay that exchange to the
dashboard and act as the administrator. The anti forgery header does not stop
a relay, because the relayed request carries it. This is the attack class
behind ESC8 against ADCS web enrolment, aimed one hop earlier at the tool that
manages the CA.

Channel binding (Extended Protection for Authentication) is the usual answer
and the service cannot offer it on this release. The web server is Kestrel,
and its Negotiate handler on .NET 10 has no setting that requires a channel
binding token and never passes one to the exchange; only HTTP.sys and IIS do.
.NET 11 adds automatic channel binding to Kestrel, and the service will pick
that up when it moves to that runtime. Until then the defence is to stop
accepting NTLM, in three steps.

**1. Make Kerberos work.** The browser asks for a Kerberos ticket for
`HTTP/<the host in the URL>`. The service runs as LocalSystem, so that name
must be registered on the server's computer account. If administrators open
the dashboard by the server's own name, the computer account's built in
`HOST` name already covers it and nothing needs registering. If they use an
alias, such as the external URL `https://certus.example.com`, register it from
an elevated prompt on a domain member:

    setspn -S HTTP/certus.example.com SERVER01$

where `SERVER01` is the server's computer name. `-S` refuses to add a name
that another account already holds, which is the one thing that silently
forces NTLM for everyone. An IP address in the URL always falls back to NTLM,
because no ticket can be issued for one. Browsers also have to be allowed to
hand out a ticket: Edge and Chrome do so for sites in the Local intranet zone
or named in the `AuthServerAllowlist` policy; Firefox needs the host in
`network.negotiate-auth.trusted-uris`.

**2. Confirm which package each sign in uses.** The service log names it, once
per administrator and package since the last start, at Information:

    Dashboard sign in by CORP\alice used Kerberos

A line that says `NTLM` means that administrator's browser could not get a
ticket: the wrong name in the URL, a missing service principal name, a
browser outside the intranet zone, or a workstation that is not domain
joined. Fix those first, and watch the log until every administrator shows
`Kerberos`.

**3. Refuse NTLM.** Set `Auth:RequireKerberos` to `true` in the settings
overlay and restart the service. A sign in that used NTLM is then answered
with a 401 and a problem document that says why, logged at Warning, and
counted on the Audit page with the other refused sign ins. The setting ships
off, because turning it on before step 1 locks every administrator out, and
the service cannot yet tell you whether your name is registered.

Windows can also refuse NTLM for the whole server, through the Group Policy
setting `Network security: Restrict NTLM: Incoming NTLM traffic` under
Computer Configuration, Windows Settings, Security Settings, Local Policies,
Security Options, set to `Deny all accounts`. Audit first with the matching
`Audit Incoming NTLM Traffic` setting and read the NTLM operational log. Be
clear about what it does: it applies to every service on that server, not just
the dashboard, so file shares, remote management and anything else that a
client reaches by IP address or without a registered name will stop
authenticating too. `Auth:RequireKerberos` is the narrower switch and is the
one to reach for first.

## Challenge validation egress

For HTTP-01 and TLS-ALPN-01 challenges, the server itself is the party that
connects out: it fetches `http://{host}/.well-known/acme-challenge/{token}` on
port 80, or opens a TLS connection on port 443 and inspects the ALPN
certificate. DNS-01 and device-attest-01 never connect to the validation
target, so nothing in this section affects them.

Because the validator runs next to the CA, those outbound connections are worth
fencing. Out of the box:

| Target | Range | Default |
|---|---|---|
| Loopback | `127.0.0.0/8`, `::1` | blocked |
| Link local, including the cloud metadata address `169.254.169.254` | `169.254.0.0/16`, `fe80::/10` | blocked |
| IPv6 unique local | `fc00::/7` | blocked |
| The literal name `localhost` | | blocked |
| RFC 1918 private ranges | `10.0.0.0/8`, `172.16.0.0/12`, `192.168.0.0/16` | **allowed** |

Every address a name resolves to is vetted at connect time, so a record that
flips between a public and a private address (DNS rebinding) does not slip
through, and IPv4 addresses wrapped in IPv6 form are unwrapped before the
check. Redirects are not followed by default, so a challenge server cannot
bounce the validator to an internal address either.

> **Why the private ranges are open by default.** An internal CA usually
> validates hosts that live on exactly `10.0.0.0/8`, `172.16.0.0/12`, and
> `192.168.0.0/16`; blocking them by default would break the product's primary
> use case on day one. The cost of the open posture: an ACME client with an
> account on your server can point the validator at internal hosts on ports 80
> and 443 and learn from the timing whether something answers there. Validation
> only succeeds on the exact expected response, so nothing is read back, but it
> is an internal reachability oracle. Once nothing you validate lives on a
> private address, turn the flag below on and that oracle is gone.

### Blocking the private ranges

If every name your CA validates resolves to a public address, set one flag in
`settings.json` in the data folder (`C:\ProgramData\Ducks in a Row`):

```json
"Certus:Acme:ChallengeValidation": {
  "BlockPrivateRanges": true
}
```

Or as an environment variable:
`Certus__Acme__ChallengeValidation__BlockPrivateRanges=true`. Restart the
service after either; the egress settings are read at startup.

With the flag on:

- An order that names a private IP address directly is refused at order time
  with `rejectedIdentifier`.
- A name that resolves to a private address fails HTTP-01 and TLS-ALPN-01
  validation as a hard policy rejection. The challenge is marked invalid and is
  not retried, because nothing transient is wrong.

### Blocking more ranges

`AdditionalBlockedCidrs` fences off anything else, in `address/prefix` form.
The checks are additive: an address that any rule blocks is blocked. For
example, to also cover the carrier grade NAT range:

```json
"Certus:Acme:ChallengeValidation": {
  "BlockPrivateRanges": true,
  "AdditionalBlockedCidrs": ["100.64.0.0/10"]
}
```

An invalid CIDR entry stops the service at startup rather than silently
weakening the fence; the reason is in the log file under
`C:\ProgramData\Ducks in a Row\logs`.

### Settings reference

All keys live in the `Certus:Acme:ChallengeValidation` section.

| Setting | Default | Purpose |
|---|---|---|
| `AllowRedirects` | `false` | Whether validation follows HTTP redirects. Leave off so a challenge server cannot redirect the validator to an internal address |
| `BlockLoopback` | `true` | Refuse loopback validation targets |
| `BlockLinkLocal` | `true` | Refuse link local targets, including the cloud metadata address |
| `BlockUniqueLocalIpv6` | `true` | Refuse IPv6 unique local targets |
| `BlockPrivateRanges` | `false` | Refuse the RFC 1918 private ranges. See above |
| `AdditionalBlockedCidrs` | `[]` | Extra `address/prefix` ranges to refuse |

This screen applies to the validator's own outbound connections only. It is not
a host firewall, and it does not constrain what the CA may issue; the allowed
domain list does that.

## Active Directory integrated DNS and DNS-01

On a new install, external account binding is required and the allowed domain
list holds the server's own Active Directory domain. Of the two, binding is the
one that matters in an Active Directory domain, and this section says why.

An Active Directory integrated zone with secure dynamic updates, the default,
lets **Authenticated Users create a record for any name that does not exist
yet**. That is how a new computer registers its own address, and it is not
limited to computers: any ordinary domain account can do it, through a dynamic
update or straight through LDAP. The account that creates a record owns it and
can change it afterwards. It cannot touch a record somebody else already owns.

A DNS-01 challenge asks for a TXT record at `_acme-challenge.<name>`, which is
a name of its own in the zone. For most hosts nobody has ever created it, so an
ordinary domain user can create it and pass the challenge for an existing
host, `web.corp.example.com` included. For a name that does not exist at all,
the same user can create its address record and pass HTTP-01 or TLS-ALPN-01
too. So in such a zone a passed challenge proves only that the requester holds
a domain account, not that they run the host.

**Binding closes this; the allowed domain list does not.** With binding
required, an ACME account can only be registered with a credential you handed
out, so a user without one never reaches the challenge. The allowed domain list
cannot help here, because the forest's own suffix is exactly the list entry and
exactly where that user can write. It keeps issuance away from names outside
your organization; it does not decide who inside it may ask. Leave binding
required, and give a credential a
[domain namespace](external-account-binding.md#domain-namespaces) when its
holder should only order names under one subdomain.

A credential holder can still do the same thing with their own credential, so
hand credentials to clients and teams you would trust with a certificate for
any name their namespace allows.

The wizard fills the list with one suffix: the primary DNS suffix of the server
it runs on. In a forest with several domains, a server in a child domain gets
that child's suffix and nothing else, so add the other domains yourself if
their clients should be served.

Removing the create right from Authenticated Users on the zone also closes the
gap, but it stops new computers from registering their own records, so treat it
as a change to your DNS design rather than to Ducks in a Row, and test it first.

## The allowed domain list

The allowed domain list on the Settings page is the name restriction: with it
switched on, an ACME order may only name the listed domains and their
subdomains. On a new install the setup wizard switches it on with the Active
Directory domain the server is joined to, and leaves it off in a workgroup,
where there is no domain to suggest. It fails closed. If the restriction is on and the list holds no
usable entry, which can only happen when `ducks-setup.json` in the data folder
was edited by hand, every order is refused until an entry is added or the
restriction is switched off, and the service log says so at Error. The same
applies when the file cannot be read before the service has loaded it once. A
read failure after a good load keeps the last good list. Switching the
restriction off is the only way to issue for any name; an empty list is never
that.

## Staying on a current release

Ducks in a Row never contacts the internet, so it cannot check whether a newer
release exists. A fix for a vulnerability reaches you through the
[security notices](https://ducksinarow.dev/notices) list, the GitHub security
advisories and the release notes, and the upgrade itself is yours to schedule
under your own change control.

What the product can do is show how old the installed release is. The About
block on the Settings page shows the release's date beside its version, with
the date of the commit it was built from rather than the time of the build, so
every build of one release shows the same date. Once that date is older than a
threshold, the block warns that a newer release may exist and links the
[releases page](https://github.com/haruspexsystems/Ducks-in-a-Row/releases).
The same block names the .NET and ASP.NET Core runtime versions the service
runs on, because patches to those arrive through Windows Update, not through
the Ducks in a Row installer: the bundle installs a runtime only when none is
present, and never updates one.

| Setting | Default | Purpose |
|---|---|---|
| `Certus:ReleaseAgeWarningDays` | `180` | How many days old the installed release may be before the Settings page warns that a newer one may exist. `0` turns the warning off, and so does any negative value; the date and the runtime versions stay shown. Set it in `settings.json` in the data folder, as for any other setting |

Nothing here sends anything: the warning is computed from the date inside the
installed binaries and the server's clock, and the links are ordinary links that
your browser follows only when you click them.

## Hardening the CA behind Ducks in a Row

Ducks in a Row is a proxy. It decides *who* may ask for a certificate and *for
which names*, then hands the request to Active Directory Certificate Services,
which decides what to issue. A hardened proxy in front of an unhardened CA still
leaves you exposed, because anything with a domain account can talk to the CA
directly and never touch Ducks in a Row at all.

### Apply the July 2026 update

CVE-2026-54121, published as "CertiGhost", is a critical elevation of privilege
in AD CS with a public proof of concept. A low privilege domain account with
network reach to the CA can drive certificate enrollment into impersonating a
domain controller, which leads to full domain compromise. Microsoft shipped the
fix on 14 July 2026.

**Install the July 2026 security update on every CA in the forest.** Nothing in
this product substitutes for that patch.

> **What Ducks in a Row does and does not do here.** The attack rides in ADCS
> request attributes: `cdc` points the CA at an attacker controlled host and
> `rmd` names the domain controller to impersonate. Those attributes travel in
> the request attribute string, which is a separate parameter of the CA call
> from the CSR. Ducks in a Row sends exactly one request attribute,
> `CertificateTemplate`, and builds it in a single place that refuses any
> template name carrying a control character, a line separator, or a Unicode
> formatting character, so an ACME client cannot append a second attribute
> through the attribute string. That closes the attribute string as a route to
> this bug. It does not fix the bug, it does not stop anyone reaching the CA by
> any other path, and it says nothing about what a client can put in the CSR,
> which the next section covers.

### What the CSR can and cannot carry

The attribute string is not the only thing a client sends. The CSR is the other,
and a Microsoft CA reads more of it than a reading of the PKCS#10 standard
suggests. Measured on a lab CA in October 2026: on an enrollee supplies subject
template, ADCS honoured a subject alternative name carried under the Microsoft
certificate extensions attribute (`szOID_CERT_EXTENSIONS`,
`1.3.6.1.4.1.311.2.1.14`) rather than the standard extension request OID, and, on
a schema version 1 template on a CA without the November 2024 update, it copied
requested Application Policies into the issued certificate (ESC15,
CVE-2024-49019). Either is a way to put a name or a capability in a certificate
that the ACME identifier check never saw.

Ducks in a Row refuses both at finalize, before anything reaches the CA. A CSR
may carry exactly one standard extension request attribute with a single value,
and that value may request only a subject alternative name, a key usage, an
extended key usage, basic constraints that ask for an end entity certificate
(cA=false and no path length, as Posh-ACME sends), or a non critical subject
key identifier that is the SHA-1 of the request's own public key; any other attribute or
requested extension, including a request for a CA certificate, is refused as
`badCSR`. After issuance, a second guard compares the certificate the CA actually
returned against the order: a DNS name or a subject common name the order did not
authorize, a subject alternative name that is not a DNS name, or an Application
Policy outside server and client authentication is refused, and the certificate
is revoked. This is defence in depth, not a substitute for patching the CA and
restricting who may enrol; a CA that honours a dangerous requested extension is
still misconfigured for every client that is not this product.

### Reduce the blast radius

Worth doing regardless of patch state, and all of it is CA and directory
configuration rather than product settings:

| Step | Why |
|---|---|
| Set `ms-DS-MachineAccountQuota` to `0` | The default of 10 lets any domain user create machine accounts, which several AD CS escalation paths need. Grant machine join to a delegated group instead |
| Enable CA auditing with `AuditFilter` set to `127` | Records every CA event, including the request attributes on each submission, so an attempt is visible afterwards. `certutil -setreg CA\AuditFilter 127`, then restart the CA service |
| Review Enroll and Autoenroll on every published template | Enroll rights held by broad groups such as Domain Users or Authenticated Users are what turn a template flaw into a domain wide one |
| Prefer templates that build the subject from Active Directory | An enrollee supplies subject template trusts the requester for the name. Ducks in a Row validates names before submitting, but a template that does not need that trust is a smaller target |
| Keep the CA off general purpose networks | The precondition for CertiGhost is network reach to the CA with a domain account. Restricting who can reach the enrollment endpoints shrinks the population that can try |

### Monitor mode: least privilege on a production CA

If you want Ducks in a Row to watch a CA before you trust it to issue from that
CA, run it in [monitor mode](monitor-mode.md). The service then
never submits a request and never revokes, and the CA team is asked for Read on
the CA, plus Request Certificates, which Authenticated Users already hold on a
default CA. It needs no Enroll on any template and no Issue and Manage
Certificates.

Monitor mode refuses every write in the product at several layers: the ACME
routes, the background workers, the dashboard endpoints, and finally the CA
client itself. Treat that as defence in depth, not as the control. The service
runs as LocalSystem, as does any paid module it loads, and anything running
under that account could call the CA directly. The rights you grant on the CA
are the control that holds whatever the software does, so grant only the ones
monitor mode needs.

### Confirming your own exposure

The service account matters as much as the CA configuration. Ducks in a Row
submits every request as its own computer account, so that account's Enroll
rights are the ceiling on what any ACME client can obtain through it. Grant
Enroll only on the templates you intend to expose over ACME, and check the
enabled template list on the setup wizard against that grant.
