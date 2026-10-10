# Device attestation (device-attest-01)

Device attestation lets a hardware backed device prove its identity to the CA
before it gets a certificate. Ducks in a Row implements the ACME
`device-attest-01` challenge from
[draft-ietf-acme-device-attest-08](https://datatracker.ietf.org/doc/draft-ietf-acme-device-attest/),
which extends RFC 8555 with two device identifier types and one attestation
challenge.

In v1 the only supported attestation format is **`apple`**, produced by Apple
Managed Device Attestation (MDA). An Apple device managed by your MDM proves,
with a key that never leaves its Secure Enclave, that it is the specific device
named in the order. Ducks in a Row verifies that proof against Apple's own
attestation root before it asks ADCS to issue.

The feature is **off by default and fails closed.** Until an administrator
creates a device attestation profile on a template, that template does not offer
`device-attest-01` at all, and an order for a device identifier is refused as if
the feature did not exist. Nothing you do elsewhere in the product turns this on
by accident.

## How it works

A device order carries a **permanent-identifier** rather than a `dns` name. Its
value is the device serial number (or the UDID), compared octet for octet.

1. The MDM pushes an ACME certificate payload to the device, pointing it at one
   of your template directories.
2. The device orders a certificate for its own permanent-identifier. If the
   template has a profile and the identifier is allowed, the order gets a single
   `device-attest-01` challenge; otherwise the order is refused (see
   [Gate modes](#gate-modes)).
3. The device builds an attestation object with its Secure Enclave key and posts
   it to the challenge. Ducks in a Row verifies it: the attestation chains to the
   Apple root, the freshness nonce matches this challenge, and the attested
   serial equals the order identifier.
4. At finalize the server binds the certificate request to the attestation: the
   CSR public key must be the exact key that was attested, and the CSR identity
   must match the order under the profile's [binding mode](#csr-identifier-binding).
5. The request goes to ADCS on the profile's template, unchanged from any other
   ACME issuance.

The security model is a three way binding: a trusted attestation authority
(Apple) vouches for the device, the attested key equals the key in the CSR, and
the attested device identifier equals the order identifier. All three must hold.

## Enabling it

Everything is configured on the **ACME** tab of the dashboard, in the **Device
attestation** card. No wizard step and no configuration file entry is involved,
so a setup wizard re-run never changes it.

1. Confirm the template you will use meets the
   [ADCS requirements](#adcs-template-requirements) below and is published and
   ACME enabled.
2. Create a **profile** on that template. Pick a
   [gate mode](#gate-modes) and a
   [CSR identifier binding](#csr-identifier-binding); the defaults (allowlist,
   cn-or-san) are the safe starting point.
3. Add the devices you will issue to. Each **allowlist entry** is one serial
   number (or UDID). An allowlist entry is required in the default gate mode: an
   empty allowlist issues to nobody.
4. Point the MDM payload at the template's directory URL and deploy it to those
   devices.

Every change applies immediately to in flight orders. There is no restart and no
cache to wait on.

## Gate modes

A profile decides which devices reaching the template may enrol.

| Mode | Behaviour |
|---|---|
| **Allowlist** (default) | Only devices whose serial or UDID is on the profile's allowlist may order. A device not on the list is refused. This is the fail closed default. |
| **Open** | Any device that passes attestation may order, with no allowlist check. This is an observation mode for a controlled fleet, not a setting to leave on in production. |

> **Why allowlist is the default.** Any genuine Apple device that can reach the
> template directory can attest its own real serial number. Without an allowlist,
> `open` mode would issue to any managed device that finds the URL. The allowlist
> is what limits issuance to the devices you decided on.

A **disabled** profile behaves exactly like no profile: the template stops
offering `device-attest-01` and device orders are refused invisibly. Disabling
is the clean way to pause a template without deleting its allowlist.

Invisibly means the refusal names no device concept and reads exactly like the
refusal for an identifier type the server does not know, whatever the client
sends: a well formed serial, an empty value, an oversize one, and a device
order mixed with a `dns` one all get the same answer. What that hides is
whether **this template** takes device orders. It does not hide that the
product implements the draft, which the version and this page already say.

## CSR identifier binding

The Apple ACME payload cannot put the device identifier where the draft's strict
mode expects it. Apple CSRs carry only RFC822, DNS, and URI subject alternative
names, never the RFC 4043 PermanentIdentifier `otherName`. Deployed practice is
to put the serial in the subject common name instead. The binding mode chooses
how strict the server is about where the identifier appears in the CSR.

| Mode | The CSR must carry the identifier as |
|---|---|
| **cn-or-san** (default) | the subject common name **or** a PermanentIdentifier SAN. This is the mode Apple clients work with. |
| **san-required** | a PermanentIdentifier SAN only. Strict draft mode. Apple CSRs cannot satisfy this; use it only for clients that emit the `otherName`. |
| **none** | the CSR need not carry the identifier at all (privacy mode). The attestation still binds the device; the certificate simply does not restate the serial. |

Two checks always run and are not configurable: the CSR public key must equal
the attested key, and any `dns` SAN on a device CSR is refused. A wrong or
unexpected value anywhere always refuses rather than issuing something loosely
matched.

> The Phase 0 lab probe confirmed ADCS passes a PermanentIdentifier `otherName`
> from the client CSR into the issued certificate untouched on an
> enrollee-supplies-subject template, with no CA wide flags. So `san-required` is
> honest on ADCS for a client that can produce the `otherName`; Apple clients
> stay on `cn-or-san` because their CSRs cannot. **Do not** enable the CA wide
> `EDITF_ATTRIBUTESUBJECTALTNAME2` flag to work around this; it is a well known
> CA security hazard and is never required here.

## ADCS template requirements

The template a profile points at is issued through the same ADCS path as any
other ACME certificate, so it must:

- **Allow the enrollee to supply the subject.** The device identity lives in the
  CSR (the CN or the PermanentIdentifier SAN). A template that builds the subject
  from Active Directory instead will not carry the device identifier.
- **Carry the Client Authentication EKU** (`1.3.6.1.5.5.7.3.2`) if the
  certificate is for device authentication, plus any other EKU your use needs.
- **Be published on the CA and ACME enabled** in Ducks in a Row, the same as a
  template used for `dns` issuance.
- **Match the device key.** Apple hardware bound keys are ECDSA on the Secure
  Enclave (P-256). The template's key requirements must accept that key, or ADCS
  refuses at finalize with `Denied by Policy Module`.

## The Apple MDM payload

Managed Device Attestation is driven by an ACME certificate payload
(`com.apple.security.acme`) that your MDM delivers to the device. The settings
that matter for attestation are:

| Payload setting | Value |
|---|---|
| Directory URL | the template's directory, `https://<server>/acme/<template>/directory` |
| Client Identifier | the device serial number (what you put on the allowlist) |
| Attest | `true` (request an attestation) |
| Hardware Bound | `true` (generate the key in the Secure Enclave) |
| Key Type | `ECSECPrimeRandom` (the Secure Enclave key type) |
| Key Size | `256` |

> Use your MDM's own interface or Apple's configuration profile reference for the
> exact key names and capitalisation; MDM vendors surface these differently.
> `Attest` and `Hardware Bound` must both be on, or the device produces an
> ordinary key with no attestation and the challenge cannot be satisfied.

The `Client Identifier` the payload sets becomes the order's permanent-identifier
and must match an allowlist entry exactly.

## External account binding does not apply

EAB (external account binding) cannot gate Apple device orders, because **the
Apple ACME payload has no place for EAB credentials.** A device managed by your
MDM cannot present an HMAC key id.

This has a concrete consequence: if EAB enforcement is set to **Required**, Apple
devices cannot register an account and cannot enrol at all. That is expected, not
a bug. The device attestation allowlist, not EAB, is the gate for device orders.
The mode applies to the whole server rather than to one template, so putting
devices on a template of their own does not help: keep EAB at Off or Optional
wherever device attestation is in use. An account a device registered before
the mode was raised keeps working, but any new registration is refused, a device
enrolling again included.

## Renewal and Apple rate limits

Apple rate limits fresh attestations per device. A device that attests too often
in a short window is told to wait, so treat each attestation as a scarce
resource:

- **Prefer longer certificate lifetimes.** Aim for 90 days or more so renewals
  are infrequent. A short lifetime that forces daily reattestation will hit
  Apple's limit.
- **The server never retries a spent attestation.** An attestation object is
  consumed once. Attestation failures are terminal for that challenge, not
  transient, so there is no server side retry loop burning through the device's
  budget.
- **The gate runs before the attestation.** A device that is not on the allowlist
  is refused at newOrder, before it spends an attestation, so a misconfigured
  fleet does not exhaust its budget against a closed gate.

## Trust anchors and Apple root rotation

The Apple Enterprise Attestation Root CA ships embedded in Ducks in a Row, pinned
by SHA-256 fingerprint and verified at load. It is shown on the trust anchor
panel as a read only built in anchor. Verification fails closed if the embedded
copy ever fails its pin.

Custom trust anchors are **additive**. You can add an anchor (by pasting its PEM
on the trust anchor panel), but a custom anchor can never shadow, disable, or
override the pinned Apple root. Adding an anchor makes the server trust
attestations that chain to it, so only an administrator can add or remove one,
and a certificate that equals a built in root is refused rather than stored as a
second copy.

Two things custom anchors are for:

- **A test or synthetic attestation authority**, so a lab rig can drive the flow
  without a real Apple device.
- **Bridging an Apple root rotation.** When Apple rotates its attestation root:
  1. Obtain the new root and add it as a custom trust anchor. Devices attesting
     under either root now verify.
  2. Update to the Ducks in a Row release that pins the new root as the built in
     anchor.
  3. Remove the custom anchor once every device has moved to the new root.

## Where refusals show up

A device order refused by the gate is recorded and surfaced on the dashboard
activity feed as **blocked by the device attestation policy**, distinct from a
domain allow list or EAB namespace refusal so you know to look at the device
attestation card. Successful `device-attest-01` validations are counted in the
Validation Methods widget alongside the `dns` challenge types.
