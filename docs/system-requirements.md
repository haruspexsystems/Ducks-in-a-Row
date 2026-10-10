# System requirements

What the server needs before you install. If you only want to get going, the
[quickstart](quickstart.md) covers the short version; this page is the full
list, including the network ports and the reason each one is open.

## Server requirements

| Requirement | Details |
|---|---|
| Operating system | Windows Server. Verified on Server 2019 and Server 2025. See the Server 2022 note below |
| Runtime | ASP.NET Core 10.0. `Ducks-in-a-Row-Setup.exe` installs it for you, offline. Install the Hosting Bundle by hand only if you use the bare MSI |
| Windows feature | `RSAT-ADCS-Mgmt`, the ADCS Remote Administration Tools |
| Processor | Two x64 cores minimum. The work is mostly waiting on input and output, being COM and RPC calls to the CA plus SQLite, with short bursts of certificate cryptography |
| Memory | 1 GB minimum, 2 GB recommended |
| Disk | About 500 MB for the application and the .NET runtime. Plan at least 5 GB free for database growth, logs and upgrades. At roughly 1000 ACME accounts renewing over three years the database reaches the low hundreds of MB, and log files are capped at 30 daily files |
| Network | TCP 5000 for HTTP and TCP 5001 for HTTPS, both configurable |
| Domain | Must be domain joined, because the CA is reached over DCOM |

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
- DCOM and RPC network access from the Ducks in a Row server to the CA server.
- The server's machine account granted **Enroll** on each certificate template
  you want to expose over ACME.
- The server's machine account granted **Read** on the CA itself. Without it
  enrolment still works, but the dashboard inventory stays empty.
- Certificate templates published to Active Directory.

The service runs as LocalSystem, so the account that needs those rights is the
server's machine account, written `DOMAIN\SERVERNAME$`. Revocation from the
dashboard additionally needs **Issue and Manage Certificates** on the CA; see
[revocation](revocation.md) for what that does and does not allow.

## Network ports

| Direction | Port | Protocol | Purpose |
|---|---|---|---|
| Inbound to the server | 5000, 5001 | TCP | ACME clients and dashboard browsers |
| Outbound to the CA | 135 | TCP | DCOM and RPC endpoint mapper |
| Outbound to the CA | 49152-65535 | TCP | DCOM and RPC dynamic ports |
| Outbound to targets | 80 | TCP | HTTP-01 challenge validation |
| Outbound to DNS | 53 | TCP and UDP | DNS-01 challenge validation |
| Outbound to targets | 443 | TCP | TLS-ALPN-01 challenge validation |

The three outbound challenge rows are needed only for the challenge types you
actually use. The server is the party that performs validation, so it needs to
reach the name being validated, not the other way round. The
[hardening guide](hardening.md) covers narrowing that egress.

`device-attest-01` needs no outbound rule at all. The device presents its
attestation in the challenge response and the server verifies it against a
trust anchor it already holds, so nothing is fetched. See
[device attestation](device-attestation.md).
