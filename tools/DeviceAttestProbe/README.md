# DeviceAttestProbe

Phase 0 diagnostic for the ACME device-attest-01 feature
(draft-ietf-acme-device-attest-08). Two jobs:

1. Answer, against a real ADCS CA, whether an RFC 4043 PermanentIdentifier
   otherName SAN in a client CSR survives into the issued certificate on an
   enrollee-supplies-subject template. Ducks in a Row passes the client CSR to
   the CA untouched (only a `CertificateTemplate:` attribute is added), so this
   passthrough is the only way the device identity can reach the issued
   certificate.
2. Record the Apple attestation facts the Phase 3 verifier will hard-code, so
   they are pinned to sources on a known date rather than pulled from memory
   during implementation.

## Running the probe

The probe must run on a domain joined host that can reach the CA (the lab
Certus host, not a workgroup dev box). The lab hosts do not have the .NET SDK
or this repository, so build on the dev box and copy the output over.

On the dev box (repo checkout plus SDK), publish a self contained build; it
runs on any x64 Windows host with no runtime installed:

```powershell
dotnet publish tools/DeviceAttestProbe -c Release -r win-x64 --self-contained true
Compress-Archive tools\DeviceAttestProbe\bin\Release\net10.0-windows\win-x64\publish\* DeviceAttestProbe-win-x64.zip
```

Copy the zip to the lab host, expand it, then run the exe as a domain account
that has Enroll permission on the chosen template:

```powershell
$env:CERTUS_PROBE_CA = "<host>\<CA name>"
$env:CERTUS_PROBE_TEMPLATE = "<template name>"   # enrollee-supplies-subject, auto-issue
.\DeviceAttestProbe.exe
```

(`dotnet run --project tools/DeviceAttestProbe` works too, but only on a
machine that has both the repository and the SDK.)

Three runs are submitted, each with a fresh RSA 2048 key and Subject
`CN=PROBE-SN-0001`:

- Run A: SAN carries only the otherName PermanentIdentifier `PROBE-SN-0001`.
- Run B: same but with an assigner OID inside the PermanentIdentifier, since
  the draft's identifier grammar (`value ["/" assigner-OID]`) round-trips
  through the assigner field and the CA may treat it differently.
- Run C: otherName plus a dNSName, to catch a policy module that keeps DNS
  names while silently dropping otherName forms.

Each run prints the SAN as constructed, the submission disposition, the issued
certificate's SAN as parsed back, and a verdict line:

```
OTHERNAME PRESERVED: yes | no | reencoded
```

`Denied` usually means template enroll permissions and answers nothing about
otherName handling; the probe says so. `UnderSubmission` means the template
requires manager approval and cannot answer the question either.

What the verdict decides: nothing in phases 1 to 4 (the default
`cn-or-san` CSR binding keeps the identity in the issued certificate via the
CN either way). It decides whether the strict `san-required` binding mode is
honest on ADCS, and what the docs say about issued certificate contents.

Never work around a stripped SAN with `EDITF_ATTRIBUTESUBJECTALTNAME2`. That
flag is CA wide and is a well known privilege escalation hazard.

## Apple attestation facts for Phase 3 (recorded 2026-07-17)

Cross-checked between step-ca source (smallstep/certificates, acme/challenge.go
on master) and Apple's published PKI. These become the `AppleAttestationOids`
constants in the Phase 3 verifier; if the verifier ever disagrees with a live
device, re-verify here first.

Leaf certificate extension OIDs (Apple device attestation certificates):

| Fact | Value |
|---|---|
| Serial number | `1.2.840.113635.100.8.9.1` |
| UDID | `1.2.840.113635.100.8.9.2` |
| sepOS version | `1.2.840.113635.100.8.10.2` |
| Nonce (freshness) | `1.2.840.113635.100.8.11.1` |

Verification facts:

- Nonce value = SHA-256 over the raw ACME challenge token string bytes
  (`sha256(ch.Token)` in step-ca; the draft's external attestation authority
  pattern where attToBeSigned is the token alone, not the key authorization).
  Compare constant time.
- attStmt map: `x5c` array of DER certificates, leaf first, then
  intermediates. authData may be absent (the draft says clients SHOULD omit
  it).
- Chain verifies to the Apple Enterprise Attestation Root CA with extended key
  usage treated as any.
- The order identifier is matched against BOTH the attested serial number and
  the attested UDID; either match is accepted (deployed practice in step-ca;
  MDM operators use either as the ClientIdentifier).

Trust anchor, downloaded 2026-07-17 from
`https://www.apple.com/certificateauthority/Apple_Enterprise_Attestation_Root_CA.pem`
(Apple Private PKI repository, https://www.apple.com/certificateauthority/private/):

| Field | Value |
|---|---|
| Subject | `CN=Apple Enterprise Attestation Root CA, O=Apple Inc., C=US` |
| Self signed | yes (ECDSA P-384, sha384ECDSA) |
| Serial | `42C0C2BB2C727C5C5EABF6F1A66F1FAC5D798737` |
| Validity | 2022-02-16 to 2047-02-20 |
| SHA-256 (DER) | `ccf59ef8fcb3017d97f8b5fa6fa90e7a3f9283f76b55ac6cf6eda8b8b949f05b` |

Phase 3 embeds this certificate as a resource in Certus.Core and checks it
against the SHA-256 above at load time, failing closed on mismatch. When Apple
rotates the root, the bridge is a custom trust anchor row added through the
admin API, followed by a pin update in a patch release.
