# Intended use

What Ducks in a Row is for, the environment it is designed to run in, what it
does, and the security properties you can rely on. The page also says what not
to do with it, how long it is supported, and who makes it.

## What it is for

Ducks in a Row lets the machines in a Windows Active Directory estate request
and renew their own TLS certificates from the organisation's existing Active
Directory Certificate Services (ADCS) enterprise certificate authority, using
the standard ACME protocol (RFC 8555). It also reads the CA's certificate
inventory, alerts administrators before certificates and certificate revocation
lists expire, and lets an administrator revoke certificates within a fixed
ceiling.

In ADCS terms it is a registration authority. It authenticates the requester,
checks that the requester controls the names it asks for, chooses the
certificate template, and only then hands the request to the CA. The CA signs
what Ducks in a Row authorises, with the CA's own key and under the CA's own
policy.

It can also run in [monitor mode](monitor-mode.md), chosen at install time, in
which it never writes to the CA: no issuance and no revocation, only the
inventory, the alerts and the CRL watch.

It is not a certificate authority, not a replacement for ADCS, and not a public
ACME service.

## The environment it assumes

- **An internal network.** ACME clients inside your estate talk to a CA inside
  your estate. Nothing in the product is designed for exposure to the internet,
  and nothing in this documentation tells you to publish it there.
- **A domain joined Windows Server.** The service runs as LocalSystem and
  reaches the CA and Active Directory as the server's computer account, with no
  stored credential. See [system requirements](system-requirements.md).
- **The CA's own permissions.** What the server may do at the CA is exactly
  what its computer account has been granted: Request Certificates and Read on
  the CA, Enroll on the templates you expose, and Issue and Manage Certificates
  only if you want revocation. The CA enforces those rights, not the product,
  and monitor mode needs fewer of them. See
  [what to ask your AD and CA team](ad-and-ca-team-request.md).
- **Administrators under change control.** Settings live in files that only
  SYSTEM and Administrators can write, and the dashboard admits only members of
  the administrator group. There is no read only role: everyone who can sign in
  can change settings, issue credentials and revoke. The product trusts those
  people, so who is in that group, and who can change `settings.json`, is part
  of your security posture. See [configuration](configuration.md).

## What it does

- **An ACME server for your CA.** Each ADCS template you choose becomes its own
  ACME directory. Clients prove control of a name with HTTP-01, DNS-01,
  TLS-ALPN-01 or `device-attest-01`, and the issued certificate comes from your
  CA, on your trust chain. See [connecting ACME clients](acme-clients.md).
- **Control over who may ask.** External account binding gates account
  registration, and an allowed domain list limits which names may be ordered.
  See [external account binding](external-account-binding.md).
- **Its own HTTPS certificate.** The server enrols and renews the certificate it
  serves the dashboard and the ACME endpoints with. See
  [configuration](configuration.md#the-servers-own-https-certificate).
- **Inventory and alerts.** The CA's certificate database, synced on a
  schedule, and email or webhook alerts before a certificate or a CRL expires.
  See [expiry alerts](alerts.md).
- **Revocation, within limits.** From the dashboard, within a capability
  ceiling and a scope you choose; ACME clients may revoke their own
  certificates. See [revocation](revocation.md).
- **A setup wizard and a dashboard**, behind Windows Integrated Authentication,
  limited to the administrator group.

## Security properties

In plain words, what you can rely on:

- **It validates every request before the CA sees it.** An ACME client must
  prove control of each name it asks for. The name must be on the allowed
  domain list when one is set, and inside the credential's namespace when
  external account binding is on. The certificate signing request may carry only
  a subject alternative name, a key usage and an extended key usage, and
  anything else is refused before submission. After issuance the certificate the
  CA returned is compared with the order, and one that carries a name or a
  capability the order did not authorise is revoked and never delivered. See
  [hardening](hardening.md#what-the-csr-can-and-cannot-carry).
- **It never holds the CA's signing key.** The CA signs; Ducks in a Row only
  submits. Taking over the server gives an attacker what the server's computer
  account may do at the CA, and nothing more.
- **The revocation ceiling cannot be raised.** No setting, break glass flag or
  dashboard control lets it revoke anything but a TLS certificate. See
  [the ceiling you cannot raise](revocation.md#the-ceiling-you-cannot-raise).
- **It never contacts the manufacturer or any third party.** No telemetry, no
  update check, no crash reporting. The only outbound connections are to systems
  you configure: your CA and directory, your SMTP server and webhook endpoints,
  the names it validates during a challenge, and the CRL distribution points it
  watches. It never installs updates by itself; see
  [upgrading](installation.md#upgrading).
- **Its files are protected.** The data folder is writable only by SYSTEM and
  Administrators, stored secrets are encrypted with a keyring kept in it, and a
  configuration file anyone else can write is refused rather than read. See
  [hardening](hardening.md#the-data-folder).
- **Monitor mode never writes to the CA.** Every write is refused at several
  layers, and the CA rights it needs do not include Enroll or Issue and Manage
  Certificates. See [monitor mode](monitor-mode.md).

## What not to do

Each of these is possible, because the product does not know your estate better
than you do, and each opens a risk the defaults are there to close.

| Do not | The risk it opens |
|---|---|
| Publish the ACME endpoint, or the dashboard, to the internet | Anyone can register an ACME account, run challenges against your names, probe the service and load the CA with requests. The product is designed for an internal network |
| Leave the `Certus:Acme:ExposeAllTemplates` break glass on | Every template the CA publishes becomes an ACME endpoint, including templates whose subject rules and purposes you never reviewed for ACME. The wizard's template selection is what limits what a client can ask for. The service logs the open posture as a warning at every start |
| Set the administrator group, `Auth:AdminGroup`, to a broad group such as Domain Users | Every member can change settings, issue and revoke credentials, revoke certificates and read the whole inventory. The dashboard has no read only role, so the group is the whole control |
| Run with external account binding off and no allowed domain list on an estate where ordinary users can create DNS records | Any domain account that can create a DNS record and answer a challenge for it can obtain a certificate for that name from your CA, under a template you exposed. Keep at least one of the two on; both is better |
| Set `Auth:RequireHttps` to `false`, except for a short lab test | Dashboard sign in and ACME traffic run over plain HTTP on port 5000, where they can be read or altered on the network |
| Enable `EDITF_ATTRIBUTESUBJECTALTNAME2` on the CA | The CA then honours a subject alternative name supplied in a request attribute by any requester (ESC6), which Ducks in a Row never asks for and cannot validate. Nothing in the product needs it. See [hardening the CA](hardening.md#hardening-the-ca-behind-ducks-in-a-row) |

The hardening guide covers the CA side in more depth, and
[configuration](configuration.md#what-the-service-refuses-to-start-with) lists
the two combinations the service refuses to start with at all.

## Support

Ducks in a Row receives security fixes until 31 December 2031, at least five
years after 1.0.0 became generally available, delivered through upgrades to the
latest release, with no backports.

The kinds of support, community and commercial, are in
[SUPPORT.md](../SUPPORT.md). How to report a vulnerability, when advisories are
published, and what a release may ship with are in
[SECURITY.md](../SECURITY.md). Security fixes reach you by
[upgrading](installation.md#upgrading).

## The manufacturer

- **Manufacturer:** Haruspex Systems B.V., registered with the Dutch Chamber of
  Commerce (KVK) under number 42142878.
- **Postal address:** Wecelostraat 3, 6901 GD Zevenaar, the Netherlands.
- **Email:** licensing@haruspex.systems for licensing and general enquiries,
  feedback@haruspex.systems for feedback, and security@haruspex.systems to
  report a vulnerability, as [SECURITY.md](../SECURITY.md) describes.
- **Website:** https://ducksinarow.dev
- **Source code and releases:**
  https://github.com/haruspexsystems/Ducks-in-a-Row

<!-- When an EU declaration of conformity exists, add its internet address to
     the list above (Cyber Resilience Act, Annex II, item 6). None exists yet,
     so nothing is shown. -->

This page is the one place the manufacturer's details are stated; the README and
the documentation index link here rather than repeat them.
