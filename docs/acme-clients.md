# Connecting ACME clients

Ducks in a Row implements RFC 8555, so any standard ACME client works. No agent
or proprietary software is needed on your endpoints.

Running Kubernetes or OpenShift? cert-manager has a page of its own:
[Kubernetes and OpenShift](kubernetes.md).

## The directory URL

Every certificate template is its own ACME endpoint:

```
https://your-server:5001/acme/<template>/directory
```

- `<template>` is the template's programmatic name (its AD `cn`) or its display
  name. Display names with spaces are accepted; the client URL encodes them. A
  display name carrying an invisible character, such as a soft hyphen left
  behind by a paste from a word processor, is refused with a 400 `malformed`
  problem document; use the programmatic name and see
  [Troubleshooting](troubleshooting.md).
- Use the HTTPS endpoint (5001) in production. Plain HTTP (5000) is for lab use
  only.
- Whether registration needs an external account binding credential depends on
  the server's enforcement mode; see
  [External account binding](#external-account-binding) below. Out of the box
  the mode is Off and clients register an account from their own key the first
  time they connect.

> **Trusting the server's TLS.** ACME clients reject an untrusted TLS
> certificate on the ACME server itself. Give Ducks in a Row a certificate your
> clients already trust (for example, one chained to your internal CA root), or
> add that root to each client's trust store. The examples below note the per
> client switch for a lab where the server still uses its self signed
> certificate.

> The example commands are representative. Exact flags vary by client version,
> so check each client's own documentation for your release.

## External account binding

The ACME page of the dashboard sets one of three enforcement modes for
external account binding (RFC 8555 section 7.3.4):

| Mode | What a registering client needs |
|---|---|
| Off (default) | Nothing. A presented binding is ignored. |
| Optional | Nothing, but a presented binding is verified and recorded. |
| Required | A valid EAB credential; registration without one is refused with `externalAccountRequired`. |

An administrator creates credentials on the ACME page. Each credential is a
**key id** plus an **HMAC key** (base64url encoded, sized for HS256, which is
what every client below signs with by default; HS384 and HS512 are also
accepted). The HMAC key is shown exactly once, right after create or
regenerate, so hand both values to the client operator then. The binding
happens once, at account registration; later orders and renewals ride the
existing account while the credential stays active (revoking a credential,
or letting it expire, suspends orders from the accounts bound to it).
Accounts that registered before the mode was raised to Required keep
working; the ACME page lists them as Unbound.

A credential can also carry a **domain namespace**: accounts bound to it may
only order certificates inside those domains, across every template. Orders
outside it are refused with `rejectedIdentifier` and a message naming the
credential.

The dashboard writes ready to paste setup for you: the panel shown right
after create or regenerate inlines the real secret, and each credential row's
**Client setup** action shows the same snippets with a placeholder for the
saved secret. The dashboard covers the first six clients below; Traefik is
listed here for its field names only. The flags per client:

| Client | Directory URL | Key id | HMAC key |
|---|---|---|---|
| certbot | `--server` | `--eab-kid` | `--eab-hmac-key` |
| win-acme | `--baseuri` | `--eab-key-identifier` | `--eab-key` |
| acme.sh | `--server`, once with `--register-account` | `--eab-kid` | `--eab-hmac-key` |
| Posh-ACME | `Set-PAServer -DirectoryUrl` | `New-PAAccount -ExtAcctKID` | `New-PAAccount -ExtAcctHMACKey` |
| cert-manager | `spec.acme.server` | `externalAccountBinding.keyID` | `externalAccountBinding.keySecretRef`, a secret holding the base64url key; see [the EAB secret](kubernetes.md#the-eab-secret) |
| Caddy | `acme_ca` | `acme_eab` block, `key_id` | `acme_eab` block, `mac_key` |
| Traefik | `caServer` | `eab.kid` | `eab.hmacEncoded` |

If a client with correct looking values is refused with `unauthorized`, the
credential may be revoked, expired, or rotated; see
[troubleshooting](troubleshooting.md) for the causes and fixes.

## Challenge types

| Type | Good for | How Ducks in a Row validates it | Outbound port it uses |
|---|---|---|---|
| HTTP-01 | Standard web servers | Fetches `http://<domain>/.well-known/acme-challenge/<token>` | 80 |
| DNS-01 | Wildcards, hosts with no inbound HTTP | Looks up the `TXT` record at `_acme-challenge.<domain>` | 53 |
| TLS-ALPN-01 | TLS only environments | Opens a TLS connection on port 443 and checks the ALPN certificate | 443 |

The Ducks in a Row server is the party that performs validation, so the server
needs outbound reachability to the domain or DNS being validated.

## Key type

| Template records | Ask for | Notes |
|---|---|---|
| An RSA provider | RSA, 2048 bits or more | The stock `Web Server ACME` template. Most clients default to an elliptic curve key, so this is the case that needs a flag |
| `ECDSA_P256`, `ECDSA_P384`, `ECDSA_P521` | An ECDSA key on the named curve | |
| `ECDH_P256`, `ECDH_P384`, `ECDH_P521` | An ECDSA key on the same curve | See below |

An `ECDH_*` template is more common than it looks. The Certificate Templates
console records ECDH when **Request Handling** has its purpose set to
"Signature and encryption", which is a default rather than an unusual choice. A
PKCS#10 certificate request cannot carry an encryption only key, so the answer is
the signature key on the same curve, and the dashboard says as much when it
generates the snippet.

Forcing RSA where the template is RSA:

| Client | Flag |
|---|---|
| certbot | `--key-type rsa --rsa-key-size 2048` |
| lego | `--key-type rsa2048` |
| acme.sh | `--keylength 2048` |
| dehydrated | `KEY_ALGO="rsa"` |
| win-acme | `--csr rsa` |

cert-manager asks for RSA 2048 unless told otherwise, so an RSA template needs
nothing, and an ECDSA template needs `privateKey` on every Certificate. See
[key type](kubernetes.md#key-type) on the Kubernetes page.

## CSR requirements

At finalize the server checks the CSR against the order before anything is
submitted to the CA:

- The subject alternative names must be DNS names matching the order's
  domains exactly, wildcard marker included. Any other SAN type (an IP
  address, an email, a UPN, a directoryName, a PermanentIdentifier) is
  refused.
- The subject common name is optional. When a CN is present, it must be one
  of the domains on the order; a descriptive value such as `CN=My Web Server`
  is refused. Public ACME CAs enforce the same rule, so a client that works
  against Let's Encrypt needs no change.
- A CSR with no SAN at all is identified by its subject CN, which then has to
  match the order the same way.

A CSR that breaks these rules is refused with `badCSR`, and the order stays
in the ready state so the client can retry with a corrected CSR.

`badCSR` means the CSR itself, and only the CSR. A finalize on an order that is
no longer ready is refused with `orderNotReady` instead, including the case where
another request finalized the same order first. Rebuilding the key and the CSR
cannot help there; re-read the order and act on the status it reports.

A CA that refuses the request is a different answer again. The finalize returns
500 with `serverInternal`, the detail carries the CA's own disposition message,
and the order becomes invalid: the CA has decided, and no CSR will change its
mind. Read the detail, fix the template or the key type, and start a new order.

That same problem document is also on the order itself, in the `error` member RFC
8555 section 7.1.3 defines, so a client that lost the finalize response or that
polls rather than reads it can fetch the order and find the reason there. It
reads word for word the same either way.

One case leaves the order's `error` empty on purpose: an order that went invalid
because a challenge failed. The reason for that failure belongs to the
authorization, so follow the order's `authorizations` URLs and read the `error`
on the failed challenge, which is what section 7.1.6 asks a client to do.

If the CA cannot be reached at all, the finalize returns 503 with
`serviceUnavailable` and the order is left alone. Retry the same finalize once
the CA is back. Nothing is lost, and the authorizations you already completed
still stand.

## Renewal timing (ARI)

The directory advertises `renewalInfo`, the ACME Renewal Information extension
(RFC 9773). A client that understands it asks the server when to renew each
certificate instead of guessing from the expiry date, with a plain
unauthenticated GET of `{renewalInfo}/{certID}`, where the identifier is built
from the certificate's Authority Key Identifier and serial number exactly as
the RFC describes. No account or signature is needed.

The response is a `suggestedWindow` sitting at roughly two thirds of the
certificate's lifetime, about 2% of that lifetime wide, with a per certificate
offset derived from the serial number. The offset is what keeps a fleet issued
in one batch from renewing in one batch, and it is deterministic, so the window
a client sees never moves between polls. The `Retry-After` header says how
often to ask again (six hours).

Two behaviors are worth knowing about:

- A **revoked** certificate answers with a window entirely in the past, which
  an ARI aware client reads as "renew immediately". This is how a revocation
  reaches your fleet without anyone touching the clients, and it works however
  the certificate was revoked: through ACME, from the dashboard, or directly at
  the CA with certutil or certsrv.msc.
- When renewing, a conforming client adds a `replaces` member to its new-order
  request naming the certificate it is replacing. The server verifies it (same
  account, at least one shared identifier) and reflects it on the order. A
  second live order naming the same certificate is refused with HTTP 409 and
  `urn:ietf:params:acme:error:alreadyReplaced`, which stops duplicate renewal
  loops; if that happens, the earlier order is the one to complete. An earlier
  order that was abandoned stops blocking once it passes its own expiry, so a
  crashed renewal attempt never locks a certificate out.

Clients that read ARI include certbot from 4.1.0, lego (checked by default since
4.20.2), Caddy from 2.8.0, and simple-acme, which follows it unless
`ScheduledTask.RenewalDisableServerSchedule` is set. cert-manager reads it only
from 1.21, and only with its alpha `ACMEUseARI` feature gate switched on; see
[renewal and ARI](kubernetes.md#renewal-and-ari). Clients that do not simply
ignore the directory member and renew on their own schedule, as before.

## certbot

```bash
# HTTP-01, certbot answers the challenge itself on port 80
certbot certonly --standalone \
  --server https://your-server:5001/acme/WebServer/directory \
  --email you@example.com \
  -d host.corp.example.com \
  --key-type rsa --rsa-key-size 2048
```

> [!WARNING]
> **Match the key type to the template.** Your client must ask for the key type
> the template wants, and templates differ. Ask for the wrong one and the CA
> policy module refuses at finalize with `Denied by Policy Module`, which reads
> like a permissions problem and is not one.
>
> The wizard's template step reports the key algorithm it read from the
> template, and the **Client setup** snippets on the dashboard's ACME page come
> with the right flags already filled in for that template. That is the reliable
> answer for your CA; the table under [key type](#key-type) is the general shape.

For a lab server with an untrusted TLS certificate, set
`REQUESTS_CA_BUNDLE` to your CA root PEM so certbot trusts the endpoint, or
install that root into the system trust store.

## win-acme (Windows)

Run `wacs.exe` and, in the menu, set the ACME server to the template directory
URL, then create a certificate. Unattended example:

```text
wacs.exe --source iis --siteid 1 ^
  --baseuri https://your-server:5001/acme/WebServer/directory
```

win-acme uses the Windows certificate trust store, so import your CA root on the
machine running it if the server certificate is not already trusted.

## Caddy

```caddyfile
{
  acme_ca https://your-server:5001/acme/WebServer/directory
  # For an internal CA, point Caddy at the root so it trusts the ACME endpoint
  acme_ca_root /etc/ssl/certs/corp-root.pem
  email you@example.com
}

host.corp.example.com {
  respond "Hello from Caddy"
}
```

## Traefik

```yaml
certificatesResolvers:
  ducks:
    acme:
      caServer: https://your-server:5001/acme/WebServer/directory
      email: you@example.com
      storage: /etc/traefik/acme.json
      httpChallenge:
        entryPoint: web
```

Traefik uses the host or container trust store. Add your CA root there if the
ACME endpoint certificate is not already trusted.

## Posh-ACME (PowerShell)

```powershell
Import-Module Posh-ACME

# Point Posh-ACME at the template directory.
# Add -SkipCertificateCheck only for a lab server with untrusted TLS.
Set-PAServer -DirectoryUrl https://your-server:5001/acme/WebServer/directory

New-PAAccount -Contact you@example.com -AcceptTOS

New-PACertificate -Domain host.corp.example.com -Plugin WebRoot `
  -PluginArgs @{ WebRootPath = 'C:\inetpub\wwwroot' }
```

## cert-manager (Kubernetes)

```yaml
apiVersion: cert-manager.io/v1
kind: Issuer
metadata:
  name: ducks-in-a-row
spec:
  acme:
    server: https://your-server:5001/acme/WebServer/directory
    caBundle: <base64 of your CA root, PEM>
    email: you@example.com
    privateKeySecretRef:
      name: ducks-account-key
    solvers:
      - http01:
          ingress:
            ingressClassName: nginx
```

cert-manager trusts only public roots unless `caBundle` names yours, and it asks
for an RSA 2048 key unless a Certificate says otherwise. Issuer or
ClusterIssuer, the EAB secret, the path an HTTP-01 check takes through your
ingress, and what is known about OpenShift are on the
[Kubernetes and OpenShift](kubernetes.md) page.

## Picking a template

Any template that was enabled in the setup wizard is reachable at
`/acme/<template>/directory`. Match the template to the certificate purpose,
for example a Web Server template for TLS server certificates. A template the
CA publishes but that was not enabled in the wizard answers
`403 not enabled for ACME`; if a directory URL returns
`404 unknown certificate template`, check the name against the templates shown
in the setup wizard.
