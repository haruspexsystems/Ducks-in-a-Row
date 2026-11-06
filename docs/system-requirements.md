# System requirements

What the server needs before you install. If you only want to get going, the
[quickstart](quickstart.md) covers the short version; this page is the full
list, including the network ports and the reason each one is open. One
installation serves one CA, so an estate with more than one issuing CA needs
one server per CA, as [several certificate authorities](several-cas.md)
describes.

## Server requirements

| Requirement | Details |
|---|---|
| Operating system | Windows Server 2019, Server 2022 with current updates, or Server 2025. Verified on Server 2019 and Server 2025; see the Server 2022 note below |
| Runtime | ASP.NET Core 10.0. `Ducks-in-a-Row-Setup.exe` installs it for you, offline. Install the Hosting Bundle by hand only if you use the bare MSI |
| Windows feature | `RSAT-ADCS-Mgmt`, the ADCS Remote Administration Tools |
| Processor | Two x64 cores minimum. The work is mostly waiting on input and output, being COM and RPC calls to the CA plus SQLite, with short bursts of certificate cryptography |
| Memory | 1 GB minimum, 2 GB recommended |
| Disk | About 500 MB for the application and the .NET runtime. Plan at least 5 GB free for database growth, logs and upgrades. At roughly 1000 ACME accounts renewing over three years the database reaches the low hundreds of MB, and the log takes at most 3,000 MB: 30 files of up to 100 MB each, one a day, with a full file rolling to `ducks-<date>_001.log` and so on |
| Network | TCP 5000 for HTTP and TCP 5001 for HTTPS, both configurable |
| Domain | Must be domain joined, because the CA is reached over DCOM |

None of these Windows Server versions is dropped during the
[support period](../SECURITY.md#support-period), which runs to 31 December 2031,
without a published decision on how its users keep receiving security fixes, so
you can plan on the version you run today.

> [!WARNING]
> **Server 2022 needs current updates first.** The .NET 10 runtime requires
> Control-flow Enforcement Technology on Server 2022, and an installation that
> has not been serviced since early 2022 does not provide it. Build 20348.587 is
> confirmed too old; check yours with `winver`. The service then crashes before
> it can write a log line, and the installer reports the misleading
> **Error 1920**. Server 2019 predates the requirement and Server 2025 ships
> with it, so neither is affected.

## Installing the prerequisites

Run these in an elevated PowerShell session on the Ducks in a Row server before
you install:

```powershell
# Install the ADCS Remote Administration Tools
Install-WindowsFeature RSAT-ADCS-Mgmt

# Verify the feature is installed
Get-WindowsFeature RSAT-ADCS-Mgmt

# Verify the .NET 10 runtime is present, after the setup bundle
# or a manual Hosting Bundle install
dotnet --list-runtimes
```

> **Why RSAT-ADCS-Mgmt is required.** Ducks in a Row talks to the certification
> authority through the ADCS COM classes, and it is the Remote Server
> Administration Tools feature that registers those classes on the system.
> Without it the COM objects cannot be created at all, and the service fails
> with `DISP_E_MEMBERNOTFOUND` (0x80020003) during certificate sync and CA
> queries. See [troubleshooting](troubleshooting.md) if you are reading that
> error now.

## ADCS requirements

To issue certificates through ADCS, all of the following must be in place:

- An Active Directory Certificate Services enterprise certification authority.
- The ADCS Remote Administration Tools (`RSAT-ADCS-Mgmt`) installed on the
  Ducks in a Row server, as above.
- DCOM and RPC network access from the Ducks in a Row server to the CA server,
  on the ports under [network ports](#network-ports).
- The server's machine account admitted by the CA server's **Certificate
  Service DCOM Access** group, which is what lets an ordinary account call the
  CA over DCOM from the network. On a default CA the group holds Authenticated
  Users, so this is usually already in place.
- The server's machine account granted **Enroll** on each certificate template
  you want to expose over ACME.
- The server's machine account granted **Request Certificates** on the CA
  itself. Authenticated Users hold it on a default CA, so this too is usually
  already in place.
- The server's machine account granted **Read** on the CA itself. Without it
  enrolment still works, but the dashboard inventory stays empty.
- Certificate templates published to Active Directory.

The service runs as LocalSystem, so the account that needs those rights is the
server's machine account, written `DOMAIN\SERVERNAME$`. Revocation additionally
needs **Issue and Manage Certificates** on the CA, whether it comes from the
dashboard, from an ACME client, or from the automatic revocation at finalize;
see [revocation](revocation.md#what-the-ca-has-to-allow) for what that does and
does not allow. [What to ask your AD and CA team](ad-and-ca-team-request.md)
lists all of these, with the firewall openings, in a form you can forward to
whoever grants them.

### CA keys in an HSM

Ducks in a Row never handles the CA's private key. Every call it makes goes to
the certification authority service on the CA server over DCOM, through the
ADCS request and administration interfaces: it submits a request, collects the
certificate the CA signed, reads the CA database, downloads the CA's own
certificate chain and asks for a revocation. Where the CA keeps its key, in the
software key storage provider Windows installs by default, in a hardware
security module (HSM) or in any other key storage provider or cryptographic
service provider, is a CA setting the service cannot see and never asks about.
Nothing on the Ducks in a Row side is configured for it.

The one place an HSM can show is how long the CA takes to answer a submission,
because the HSM signs each certificate. That time is spent inside the CA call
the service makes while it answers an ACME client's finalize request, so the
client sees a slightly slower finalize response and nothing else; the order
status it reads afterwards is the same as with any other CA.

What has been verified: issuing, revoking and inventory sync against CAs whose
key sits in the default software key storage provider, on Server 2019 and
Server 2025. What has not: any CA whose key sits in an HSM, and any provider
other than the default. Nothing in the design depends on the provider, but
until a CA with such a key has been measured, the honest statement is that it
has not been verified.

## Network ports

| Direction | Port | Protocol | Purpose |
|---|---|---|---|
| Inbound to the server | 5001 | TCP | ACME clients and dashboard browsers, over HTTPS |
| Inbound to the server | 5000 | TCP | Optional. With the default settings it only redirects to HTTPS on 5001 |
| Outbound to the CA | 135 | TCP | DCOM and RPC endpoint mapper |
| Outbound to the CA | 49152-65535 | TCP | DCOM and RPC dynamic ports |
| Outbound to targets | 80 | TCP | HTTP-01 challenge validation |
| Outbound to DNS | 53 | TCP and UDP | DNS-01 challenge validation |
| Outbound to targets | 443 | TCP | TLS-ALPN-01 challenge validation |
| Outbound to CRL distribution points | 80, 389, 443 | TCP | Optional. CRL expiry alerts, over HTTP and LDAP, and HTTPS for any https location |
| Outbound to the mail server | 587 by default | TCP | Optional. Email alerts over SMTP |
| Outbound to webhook endpoints | As configured | TCP | Optional. Webhook alerts |

The installer opens 5000 and 5001 in this server's own firewall and nothing
upstream of it.

The three outbound challenge rows are needed only for the challenge types you
actually use. The server is the party that performs validation, so it needs to
reach the name being validated, not the other way round. The
[hardening guide](hardening.md) covers narrowing that egress.

`device-attest-01` needs no outbound rule at all. The device presents its
attestation in the challenge response and the server verifies it against a
trust anchor it already holds, so nothing is fetched. See
[device attestation](device-attestation.md).
