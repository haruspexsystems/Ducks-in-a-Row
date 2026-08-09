# Development Environment Setup

## Prerequisites

- [.NET 10 SDK](https://dotnet.microsoft.com/download/dotnet/10.0) (10.0.3xx or later)
- Windows 10/11 or Windows Server 2019+ (required for COM interop)
- VS Code with recommended extensions, or Visual Studio 2022

## Building and Testing

```bash
# Restore, build, and test
dotnet restore
dotnet build
dotnet test

# Run the web host (development mode)
dotnet run --project src/Certus.Web
# Health check: http://localhost:5000/health
```

## ADCS Lab CA Setup (for Integration Testing)

Integration testing against a real ADCS CA requires a lab environment. You don't need this for day-to-day development — the `MockAdcsClient` provides realistic behavior.

### Option 1: Windows Server VM with ADCS Role

1. **Create a Windows Server 2019/2022 VM** (Hyper-V, VMware, or cloud)
2. **Promote to Domain Controller** (or join an existing test domain):
   ```powershell
   Install-WindowsFeature AD-Domain-Services -IncludeManagementTools
   Install-ADDSForest -DomainName "certus.local" -SafeModeAdministratorPassword (ConvertTo-SecureString "P@ssword1" -AsPlainText -Force)
   ```
3. **Install ADCS**:
   ```powershell
   Install-WindowsFeature ADCS-Cert-Authority -IncludeManagementTools
   Install-AdcsCertificationAuthority -CAType EnterpriseRootCA -CACommonName "Certus-TestCA" -Force
   ```
4. **Verify CA is running**:
   ```powershell
   certutil -ping
   # Expected: "CertUtil: -ping command completed successfully."
   ```
5. **Get the CA config string** (needed for Certus configuration):
   ```powershell
   certutil -getconfig
   # Output: "dc01.certus.local\Certus-TestCA"
   ```

### Option 2: Use the Mock Client (Recommended for Development)

The `MockAdcsClient` in `Certus.Core` generates real X.509 certificates using BouncyCastle. It:

- Returns realistic CA info and template lists
- Issues valid X.509 certs signed by a mock CA
- Supports pending/approval workflow simulation
- Works on any OS (no Windows/ADCS dependency)

To use mock mode, do NOT configure `Certus:CaConnectionString` in appsettings.json. The Web host will be updated in later phases to fall back to the mock client when no CA is configured.

## COM Interop Notes

### Threading

ADCS COM objects (ICertRequest2, ICertAdmin2, ICertView2) support **free-threading (MTA)**. This means:
- They work with ASP.NET Core's default thread pool (MTA threads) ✅
- No STA thread required ✅
- Individual COM instances are NOT thread-safe — create per-operation and release

### Testing COM Interop

Integration tests that hit a real CA are tagged with `[Trait("Category", "Integration")]` and skipped in CI:

```bash
# Run only unit tests (no real CA needed)
dotnet test --filter "Category!=Integration"

# Run integration tests (requires CA connectivity)
dotnet test --filter "Category=Integration"
```

### DCOM Configuration

For the Certus server to communicate with a remote CA via DCOM:

1. The Certus service account must have DCOM launch/access permissions on the CA server
2. The CA server's firewall must allow DCOM/RPC traffic (TCP 135 + dynamic ports)
3. The Certus server must be domain-joined to the same forest as the CA
4. The Certus service account must have the "Read" permission on the CA itself, granted
   via the Certificate Authority console (CA Properties -> Security). This is required for
   the dashboard certificate sync, which reads the CA database through the certificate view
   interface (ICertView). It is a separate permission from certificate request/submission:
   without it, enrollment still works but the dashboard shows no certificates and the service
   log reports "CA view access denied".

## Project Architecture

```
Certus.Core    (net10.0)         → Domain models, interfaces, EF Core
Certus.Adcs    (net10.0-windows) → COM interop (CertRequest, CertView, CertAdmin coclasses, dispatched through IDispatch)
Certus.Web     (net10.0)         → ASP.NET Core host (ACME + Dashboard)
Certus.Service (net10.0-windows) → Windows Service wrapper + DI composition root
```

`Certus.Web` does NOT reference `Certus.Adcs` directly (TFM incompatibility). Instead, it programs against `IAdcsClient` from `Certus.Core`. The `Certus.Service` project wires the concrete `AdcsClient` via dependency injection.
