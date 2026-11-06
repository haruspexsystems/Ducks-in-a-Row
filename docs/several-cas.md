# Several certificate authorities

One installation of Ducks in a Row connects to one certificate authority. That
is the free product as released, and [licence and paid module](licence.md) says
so. An estate that has been tidied up often has more than one issuing CA under
an offline root: a root plus two issuing CAs is a common shape, and a utility or
a manufacturer often has one issuing CA for the office network and one for the
operational network. This page says what the supported arrangement is today,
how the installations relate to each other, and what you do not get from it.

The short version: **one installation per issuing CA**, each on its own server,
with its own data folder, database, settings and dashboard. The two never talk
to each other. Everything you configure once in a single CA estate, you
configure once per installation here.

## One installation per issuing CA

The installer registers one service per server, `DucksInARow`, with one data
folder whose location it records in the registry; see
[what the installer does](installation.md#what-the-installer-does). So an
installation per issuing CA is a server per issuing CA. A virtual machine is
fine, and the [system requirements](system-requirements.md) are the same for
each.

Each installation is complete on its own, and nothing is shared:

- **Its own data folder and database.** `ducks.db`, `settings.json`,
  `ducks-setup.json`, the Data Protection keyring, the logs and the licence
  folder all live in that server's data folder, as
  [backup and restore](backup-and-restore.md) lists them. Back up each
  installation separately.
- **Its own CA connection.** Each installation's setup wizard names one CA, and
  that is the CA it syncs the inventory from, issues from and revokes on.
- **Its own dashboard**, at that server's external URL, with its own
  administrator group.

Some things are the same on both and have to be entered twice:

- **Alert recipients.** The SMTP settings on each Settings page, and the
  webhook block in each `settings.json`. See [expiry alerts](alerts.md).
- **Allowed domains, templates and revocation scope.** Each installation's
  setup wizard records its own `ducks-setup.json`.
- **External account binding credentials.** A credential is issued by one
  installation and registers an account there only. See
  [external account binding](external-account-binding.md).
- **The ACME directory URL.** The URL names the server and the template, so
  each installation has its own set:

  ```text
  https://ducks-it.corp.example.com:5001/acme/WebServer/directory
  https://ducks-ot.corp.example.com:5001/acme/WebServer/directory
  ```

  An ACME client enrols from whichever CA its directory URL points at. A
  machine that needs a certificate from each CA runs two client
  configurations, one per URL. See
  [connecting ACME clients](acme-clients.md#the-directory-url).

## The OT pattern

The common reason for a second issuing CA is a separate operational technology
zone with a CA of its own, where nothing may write to the CA without a change
request. The supported shape is an installation in the OT zone, in
[monitor mode](monitor-mode.md), against the OT issuing CA, while the IT
installation issues from the IT CA.

Monitor mode is Ducks in a Row with issuance switched off. In the words of the
monitor mode page: the service watches your certificate authority and never
writes to it. It keeps the certificate inventory, sends expiry alerts and watches
the revocation lists, and it never submits a certificate request and never
revokes one. Monitor mode is part of the free tier, on a production CA too, so
the OT installation costs nothing extra.

### What the OT installation needs

The rights and openings below are copied from
[what monitor mode needs](monitor-mode.md#what-it-needs). None of them is a
right only issuance or revocation needs, and nothing reaches the IT CA.

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
Manage Certificates**. [What to ask your AD and CA team](ad-and-ca-team-request.md)
puts it the same way: in monitor mode, Read on the CA, plus the Request
Certificates a default CA already grants, is the whole request.

So the firewall openings for the OT installation run from the OT server to the
OT CA, to the OT CA's CRL distribution points, and to a domain controller for
the LDAP locations. A CRL distribution point served over https also needs TCP
443, which the [network ports](system-requirements.md#network-ports) table
lists. Nothing is opened from the OT zone to the IT CA, and nothing from the IT
installation to the OT CA. Add to that only what every installation has: TCP
5001 inbound for the dashboard, and SMTP or the webhook endpoint when alerts
are configured, both from the same ports table. The three outbound challenge
validation rows in that table are not needed, because monitor mode never
validates a challenge.

If the OT CA later needs issuance, [switching to issuance](monitor-mode.md#switching-to-issuance)
is a rights grant, a registry value and a restart, never a reinstall.

## The shared root's revocation list

Both issuing CAs chain to the same offline root, and each installation watches
the revocation lists of every CA in the chain of the CA it is connected to,
the root included. The root's CRL is read from the distribution points named on
the connected CA's own certificate;
[where each CRL is read from](alerts.md#where-each-crl-is-read-from) describes
it. Two issuing CAs signed by one root normally carry the same distribution
points, so both installations read the same root CRL and each one runs its own
warning ladder against it.

**The root warning therefore arrives twice.** At each step of the ladder, 30,
14, 7 and 1 days before expiry by default and once more when the CRL expires,
each installation sends its own alert, to its own recipients, naming the root
CA and the CRL number in the payload. The ladder and its thresholds are the
ones [revocation lists](alerts.md#revocation-lists) describes, shared with
certificate expiry. Two
alerts with the same CA name and CRL number from two servers are not a bug and
not a sign that one installation is reading the wrong CRL: it is one CRL being
watched from two places, which is exactly what two independent installations
do. Call it the **duplicate root warning** when you brief whoever receives the
alerts, so that it is expected rather than filed.

There is no setting that tells one installation to leave the root to the other.
`Certus:Alerts:Crl:Enabled` watches every CA in the chain or none, so turning
it off on one server would also silence that server's warnings about its own
CA's CRLs. Leave it on in both. If your alert receiver deduplicates, key on the
CA name and the CRL number the payload carries, not on the sending server.

## The forest rule

The server must be domain joined in the CA's forest: the CA authenticates the
server's computer account through Active Directory, and the service reads
certificate templates from the forest's directory.
[What to ask your AD and CA team](ad-and-ca-team-request.md#what-to-ask-for)
lists it as a requirement that always applies, and the
[quickstart](quickstart.md#before-you-start) starts with it.

So where IT and OT are separate forests, they are separate installations, one
server joined to each forest, and that stays true whatever a later release adds
about covering more than one CA from one installation. A licence bound to a
forest follows the same line; see [forest binding](licence.md#forest-binding).

## What you do not get

Two installations are two products running side by side, and nothing joins
them:

- **No single inventory.** Each dashboard lists the certificates of its own CA.
  Finding a certificate means knowing which CA issued it, or searching both.
- **No single alert configuration.** Recipients, thresholds and the webhook are
  set once per installation, and a change is made twice.
- **No single dashboard.** Two external URLs, two administrator groups, two
  Settings pages, two licence cards.

The [licence page](licence.md) states that the paid tier adds capabilities
beside the core, such as covering more than one certificate authority. That is
the whole of what is promised: no date, and no description of what the
capability will look like. Nothing on this page changes when it arrives, because
the one installation per CA arrangement stays supported.

## Two installations and the free tier

Two installations of one organisation, each connected to one CA, are two free
installations. Nothing in the licence counts organisations: the free tier is
counted per installation and per CA.
