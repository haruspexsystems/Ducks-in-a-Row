# Connecting ACME clients

Ducks in a Row implements RFC 8555, so any standard ACME client works. No agent
or proprietary software is needed on your endpoints.

## The directory URL

Every certificate template is its own ACME endpoint:

```
https://your-server:5001/acme/<template>/directory
```

- `<template>` is the template's programmatic name (its AD `cn`) or its display
  name. Display names with spaces are accepted; the client URL encodes them.
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
| cert-manager | `spec.acme.server` | `externalAccountBinding.keyID` | `externalAccountBinding.keySecretRef`, a secret holding the base64url key |
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

## certbot

```bash
# HTTP-01, certbot answers the challenge itself on port 80
certbot certonly --standalone \
  --server https://your-server:5001/acme/WebServer/directory \
  --email you@example.com \
  -d host.corp.example.com \
  --key-type rsa --rsa-key-size 2048
```

> **Key type.** If your ADCS template uses an RSA CSP (the default
> `Web Server ACME` template does), your ACME client must request an RSA key.
> Most modern clients default to elliptic curve keys, which the CA policy
> module rejects at finalize with `Denied by Policy Module`. The last line
> above forces RSA for certbot. Other clients: lego `--key-type rsa2048`,
> acme.sh `--keylength 2048`, dehydrated `KEY_ALGO="rsa"`.

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

## Picking a template

Any template that was enabled in the setup wizard is reachable at
`/acme/<template>/directory`. Match the template to the certificate purpose,
for example a Web Server template for TLS server certificates. A template the
CA publishes but that was not enabled in the wizard answers
`403 not enabled for ACME`; if a directory URL returns
`404 unknown certificate template`, check the name against the templates shown
in the setup wizard.
