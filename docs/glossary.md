# Glossary

Short, plain explanations of the terms used across these guides.

### ACME

A standard protocol (RFC 8555) for requesting and renewing certificates
automatically. It is the same protocol Let's Encrypt uses on the public
internet. Ducks in a Row speaks ACME on your internal network.

### ACME client

A program that requests certificates over ACME, such as certbot, win-acme,
Caddy, Traefik, or Posh-ACME. It runs on the machine that needs a certificate.

### ADCS (Active Directory Certificate Services)

The Microsoft certificate service built into Windows Server. It runs your
internal certificate authority. Ducks in a Row sits in front of ADCS and lets
ACME clients enrol from it.

### CA (Certificate Authority)

The system that issues and signs certificates. In this product the CA is your
ADCS server.

### Certificate template

A profile on the CA that decides what a certificate is for and what it may
contain, for example a "Web Server" template for TLS server certificates. Ducks
in a Row exposes each template as its own ACME endpoint.

### ACME directory

The starting URL an ACME client connects to. Ducks in a Row gives each template
its own directory URL in the form `https://your-server:5001/acme/<template>/directory`.

### Challenge

The check an ACME server runs to confirm you control the name you are asking a
certificate for. Ducks in a Row supports three types:

- **HTTP-01:** the server fetches a token over HTTP on port 80.
- **DNS-01:** the server looks up a `TXT` record in DNS. Good for wildcards.
- **TLS-ALPN-01:** the server checks a certificate over a TLS connection on
  port 443.

### RSAT (Remote Server Administration Tools)

Optional Windows features for managing server roles from another machine. Ducks
in a Row needs the ADCS part (`RSAT-ADCS-Mgmt`) because it registers the COM
components used to talk to the CA. Install it with
`Install-WindowsFeature RSAT-ADCS-Mgmt`.

### DCOM and RPC

The Windows technologies Ducks in a Row uses to call the CA over the network.
They need TCP port 135 plus a range of dynamic ports (49152 to 65535) open to
the CA.

### Machine account

The Active Directory account of the Windows computer itself, written with a
trailing `$` (for example `DUCKS-SERVER$`). Ducks in a Row acts as this account,
so the CA permissions are granted to the machine account, not to a person.

### Self signed certificate

A certificate a server generates for itself, with no trusted authority behind
it. Ducks in a Row uses one for HTTPS until you give it a certificate your
clients already trust. Browsers and ACME clients warn about self signed
certificates.
