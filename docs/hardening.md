# Hardening

Ducks in a Row ships with defaults that favour first issuance on an internal
network. This page collects the optional lockdowns and explains the reasoning
behind each default, so an open posture is an informed choice rather than an
accident.

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
> `rmd` names the domain controller to impersonate. Ducks in a Row sends exactly
> one request attribute, `CertificateTemplate`, and builds it in a single place
> that refuses any template name carrying a control character, so an ACME client
> cannot append a second attribute through this product. That closes Ducks in a
> Row as a route to the bug. It does not fix the bug, and it does not stop
> anyone reaching the CA by any other path.

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

### Confirming your own exposure

The service account matters as much as the CA configuration. Ducks in a Row
submits every request as its own computer account, so that account's Enroll
rights are the ceiling on what any ACME client can obtain through it. Grant
Enroll only on the templates you intend to expose over ACME, and check the
enabled template list on the setup wizard against that grant.
