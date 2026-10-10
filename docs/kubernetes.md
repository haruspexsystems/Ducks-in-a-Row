# Kubernetes and OpenShift

Workloads in a Kubernetes cluster get their certificates from cert-manager, and
often from a CA the cluster keeps for itself, which nothing outside the cluster
trusts. cert-manager's built in ACME issuer can ask Ducks in a Row instead. The
certificates then chain to the ADCS root your organisation already trusts. The
cluster needs no plugin, holds no Active Directory account and no rights on the
CA, and one scoped credential can decide which names it may order.

This page covers cert-manager on Kubernetes, and what is known about OpenShift.
For other clients, see [connecting ACME clients](acme-clients.md).

> **What has been run.** Our regular test cycle runs cert-manager against a real
> ADCS certificate authority: a namespaced Issuer, a Certificate with an RSA
> key, the Ingress annotations, HTTP-01 through ingress-nginx, and DNS-01. Not
> yet run against Ducks in a Row: trusting the server over HTTPS with
> `caBundle`, external account binding, a ClusterIssuer, an ECDSA template,
> renewal and ARI, a challenge that fails, and anything on OpenShift. Sections
> that rely on those say so, and what they describe is read from the server's
> code and from cert-manager's own code and documentation.

## Before you start

On the Ducks in a Row side:

- The template is enabled for ACME in the setup wizard. One that is not
  answers 403, "not enabled for ACME".
- If the allowed domain list is on, the cluster's host names are on it.
- The external account binding mode suits you, and a credential exists if the
  mode is Required or you want the cluster's orders limited to its own domains.
  See [external account binding](external-account-binding.md).
- The server's External URL is the name the cluster will use to reach it. See
  [pointing at a template](#pointing-at-a-template).
- The server has enrolled its own HTTPS certificate from your CA. See
  [giving clients a TLS certificate they trust](quickstart.md#giving-clients-a-tls-certificate-they-trust).
- The server can reach the cluster's ingress on TCP 80, and its DNS resolves the
  certificate names to that ingress. See [HTTP-01 through your ingress](#http-01-through-your-ingress).

On the cluster side:

- cert-manager 1.11 or later, the first release with `caBundle`. Use a release
  cert-manager still supports.
- An ingress controller that answers plain HTTP on port 80.

## Issuer or ClusterIssuer

Each one is an ACME account on the server. They differ in who can use them and
where their secrets live.

| | Issuer | ClusterIssuer |
|---|---|---|
| Issues for | Certificates in its own namespace | Certificates in every namespace |
| Reads its secrets from | Its own namespace | The cluster resource namespace: `cert-manager`, unless the controller's `--cluster-resource-namespace` flag changed it |
| Accounts on the server | One per Issuer | One for the cluster |

**Not yet run against Ducks in a Row:** a ClusterIssuer. Nothing on the server
tells the two apart; both register an account the same way.

Choose by who owns the host names. If each team owns its own names, give each
team's namespace its own Issuer and each team its own credential, with a domain
namespace listing that team's domains. A team can then order only its own
names, and revoking one team's credential leaves the others alone. If one
platform team owns every name, a single ClusterIssuer with one credential is
simpler.

The word namespace means two unrelated things here. A Kubernetes namespace is
where an Issuer and its secrets live. A domain namespace belongs to an EAB
credential and lists the DNS domains its accounts may order; see
[domain namespaces](external-account-binding.md#domain-namespaces). The pattern
above maps one of each to one team.

## Start from the dashboard manifest

The dashboard writes the manifest for you. On the **ACME** page, open
**Credentials**, create a credential, and pick **cert-manager** in the setup
panel. The panel shown right after create inlines the real HMAC key. Later, a
credential row's **Client setup** shows the same manifest with a placeholder
where the key goes, because the key is shown only once.

The manifest holds three things:

- the `kubectl create secret` line that stores the HMAC key,
- an `Issuer` pointed at the template's directory, carrying the credential's
  key id and a `caBundle` placeholder,
- a sample `Certificate` whose `privateKey` already matches the template.

Before you apply it:

1. Replace the `caBundle` placeholder; see
   [trusting the ACME endpoint](#trusting-the-acme-endpoint). Left in place, it
   makes `kubectl apply` refuse the manifest.
2. Set the email, and set `ingressClassName` to your ingress controller's class.
3. Pick the namespace, and give the secret line and `kubectl apply` the same
   `-n`.
4. For a ClusterIssuer, change the Issuer's kind and the Certificate's
   `issuerRef` kind to `ClusterIssuer`, and create the secret in the cluster
   resource namespace instead.

The Issuer it produces looks like this:

```yaml
apiVersion: cert-manager.io/v1
kind: Issuer
metadata:
  name: ducks-in-a-row
  namespace: team-a
spec:
  acme:
    server: https://ducks.corp.example.com:5001/acme/WebServer/directory
    caBundle: <base64 of your CA root, PEM>
    email: you@example.com
    privateKeySecretRef:
      name: ducks-account-key
    externalAccountBinding:
      keyID: <key id from the dashboard>
      keySecretRef:
        name: ducks-eab
        key: secret
    solvers:
      - http01:
          ingress:
            ingressClassName: nginx
```

Leave out `externalAccountBinding` if the enforcement mode is Off and you are not
using a credential.

## The EAB secret

**Not yet run against Ducks in a Row:** external account binding with
cert-manager.

Store the HMAC key exactly as the dashboard shows it:

```bash
kubectl -n team-a create secret generic ducks-eab --from-literal=secret='<HMAC key>'
```

- The key is already base64url encoded: 43 characters, no padding. Store it
  exactly as shown, and do not encode it again, even though cert-manager's own
  documentation shows an encoding step for keys that arrive raw. cert-manager
  decodes the stored value and uses the result as the HMAC key as it stands, so
  a key encoded twice, or stored with a trailing newline (as when a file written
  by `echo` is loaded with `--from-file`), gives the wrong key. The server then
  refuses the registration with 403 `unauthorized` and
  `External account binding signature verification failed.` A value that is not
  base64url at all fails earlier, inside cert-manager, with
  `failed to decode external account binding key data`. Use `--from-literal`,
  as above.
- The binding happens once, when cert-manager registers its account. From then
  on the account key, stored in the secret `privateKeySecretRef` names, is the
  cluster's identity. Keep it, and back it up with the cluster's other secrets.
- One credential can bind any number of accounts. A rebuilt cluster, a second
  cluster or an extra Issuer registers a new account against the same
  credential, and the ACME page lists every account bound to it.
- Regenerating a credential keeps its key id and every account already bound to
  it. Only a new registration needs the new key, but update the Kubernetes
  secret anyway so the next one works.
- An account stays bound to the credential it registered with. Pointing an
  existing Issuer at a different key id changes nothing on the server, and if
  the old credential is revoked, that account's orders are refused with
  `unauthorized`. To move an Issuer to a new credential, give
  `privateKeySecretRef` a new name as well, so cert-manager creates a new
  account key and registers it with the new binding.
- Revoking a credential, or letting it expire, suspends orders from every
  account bound to it; see
  [revoking, expiring, and the difference](external-account-binding.md#revoking-expiring-and-the-difference).

## Pointing at a template

`spec.acme.server` is the template's directory URL:

```text
https://ducks.corp.example.com:5001/acme/<template>/directory
```

- Use the host name in the server's External URL, exactly. The certificate the
  server enrols for itself names that host and no other, so cert-manager refuses
  any other name for it. And once the External URL is set, every URL the server
  hands back, for new accounts, orders and certificates, is built from it, so
  the cluster has to resolve and reach that name whatever the directory URL
  says. The dashboard's manifest already uses it.
- Use HTTPS on port 5001. Plain HTTP on port 5000 is for lab use only, and by
  default it redirects to HTTPS.
- Every template is its own directory, so each template needs its own issuer.
  Name it by its programmatic name, its AD `cn`, to keep spaces out of the URL.

## Trusting the ACME endpoint

**Not yet run against Ducks in a Row:** `caBundle`. Our test cycle reaches the
server over plain HTTP.

Once the server has enrolled its own certificate, that certificate comes from
your ADCS CA, and cert-manager trusts only the public roots in its container,
so it has to be told about yours. Without that the Issuer never becomes ready,
and reports `x509: certificate signed by unknown authority`. A server still
serving its self signed certificate is no use here: that certificate names only
`localhost` and the server's short machine name, not the External URL host, so
enrol one first.

Put your root certificate in `caBundle`, as PEM, base64 encoded on one line:

```bash
base64 -w0 corp-root.pem
```

```powershell
[Convert]::ToBase64String([IO.File]::ReadAllBytes('corp-root.pem'))
```

To get the PEM, export the root on any domain joined Windows machine: in
`certlm.msc`, open **Trusted Root Certification Authorities**, then
**Certificates**, right click your root, choose **All Tasks**, **Export**, and
pick **Base-64 encoded X.509**. With an issuing CA under an offline root, put
the issuing CA's certificate in the bundle after the root, so the chain verifies
even when the server does not send it.

- Never set `skipTLSVerify`. It turns off verification of the server entirely,
  and cert-manager's own documentation marks it insecure.
- cert-manager is written in Go, which is stricter than Windows about two things
  older ADCS estates run into. It refuses a certificate signed with SHA-1
  anywhere below the root, so a CA that still signs with SHA-1 has to move to
  SHA-256 first. And it never takes a host name from a certificate's common
  name, only from its subject alternative names. The certificate the server
  enrols for itself carries the External URL host as a DNS name, so it passes; a
  certificate you install by hand has to as well.

## HTTP-01 through your ingress

Ducks in a Row validates a challenge itself, from the Windows server it runs on.
A challenge goes like this: cert-manager starts a small solver pod, routes
`/.well-known/acme-challenge/<token>` to it through your ingress controller,
checks that it can fetch the token itself, then tells the server it is ready.
The server then fetches `http://<name>/.well-known/acme-challenge/<token>` on
port 80.

What that asks of your network:

- The server must reach the ingress on TCP 80; see
  [network ports](system-requirements.md#network-ports). In a segmented network
  this is the one firewall rule to ask for, from the server to the ingress
  addresses.
- The server resolves the name with its own DNS servers and connects to the
  first address it gets back. On the server, the name has to resolve to the
  ingress, not to an address only the cluster can reach.
- By default the server does not follow redirects (`AllowRedirects` is off). If
  your ingress sends plain HTTP to HTTPS for the whole host, exempt
  `/.well-known/acme-challenge/` from that, or the challenge fails with the
  redirect's status, for example `server returned HTTP 308`.
- By default a name that resolves to a loopback, link local or IPv6 unique local
  address is refused, and so is a name with any such address among its answers.
  If `BlockPrivateRanges` or `AdditionalBlockedCidrs` is set in
  [challenge validation egress](hardening.md#challenge-validation-egress), make
  sure the ingress addresses are still allowed.

cert-manager's own check, the one before it tells the server it is ready, runs
from inside the cluster through the cluster's DNS. If the cluster cannot resolve
your internal zone, the challenge sits pending and the server is never asked;
our test cycle hit exactly this. Make the zone resolvable in the cluster, for
example by forwarding it from CoreDNS to your DNS servers. From cert-manager
1.21 you can instead set `waitInsteadOfSelfCheck` on the solver, which skips the
check and waits a fixed time.

HTTP-01 cannot prove a wildcard name, so a wildcard order is offered DNS-01
only. The server looks up `_acme-challenge.<name>` with its own DNS servers, so
cert-manager's DNS-01 solver has to write into a zone those servers answer from.
Setting one up for an internal zone is outside this page; cert-manager's
documentation lists the providers, and our test cycle has run its RFC 2136
solver. The server also offers TLS-ALPN-01, but cert-manager has no solver for
it.

## Requesting a certificate

A `Certificate` asks for one:

```yaml
apiVersion: cert-manager.io/v1
kind: Certificate
metadata:
  name: app
  namespace: team-a
spec:
  secretName: app-tls
  dnsNames:
    - app.corp.example.com
  issuerRef:
    name: ducks-in-a-row
    kind: Issuer
  privateKey:
    algorithm: RSA
    size: 2048
```

Or annotate an Ingress, and cert-manager creates the Certificate from the
Ingress's `tls` section:

```yaml
metadata:
  annotations:
    cert-manager.io/issuer: ducks-in-a-row
    cert-manager.io/private-key-algorithm: RSA
    cert-manager.io/private-key-size: "2048"
```

For a ClusterIssuer the annotation is `cert-manager.io/cluster-issuer`, and a
Certificate names it with `kind: ClusterIssuer` in its `issuerRef`.

What the server accepts is set out under
[CSR requirements](acme-clients.md#csr-requirements). For a Certificate that
means:

- DNS names only. The server refuses IP address identifiers and every other kind
  of subject alternative name, so leave `ipAddresses`, `uris` and
  `emailAddresses` unset.
- `commonName` is optional. If you set it, it has to be one of the `dnsNames`.
- `duration` changes nothing. The template sets the certificate's lifetime.
  cert-manager sends a requested lifetime only when the issuer sets
  `enableDurationFeature`, and the server then accepts the request and still
  issues for the template's lifetime.

## Key type

The template decides the key type, and cert-manager defaults to RSA: with no
`privateKey` it asks for RSA 2048. So an RSA template needs nothing, and an
ECDSA template needs the setting on every Certificate, or the annotations on
every Ingress.

| Template records | privateKey |
|---|---|
| RSA, minimum 2048 | Nothing, or `algorithm: RSA` and `size: 2048` |
| RSA, minimum above 2048 | `algorithm: RSA` and `size: 4096`. cert-manager accepts only 2048, 4096 and 8192, so a 3072 minimum needs 4096 |
| `ECDSA_P256` | `algorithm: ECDSA` and `size: 256` |
| `ECDSA_P384` | `algorithm: ECDSA` and `size: 384` |
| `ECDSA_P521` | `algorithm: ECDSA` and `size: 521` |
| `ECDH_P256`, `ECDH_P384`, `ECDH_P521` | The ECDSA key on the same curve; see [key type](acme-clients.md#key-type) |

**Not yet run against Ducks in a Row:** an ECDSA template. Our test cycle issues
with an RSA key.

The dashboard's manifest fills this in for the template you pick, and the setup
wizard shows the algorithm it read from the template.

A key the template does not accept is refused by the CA's policy module, not by
Ducks in a Row. The finalize answers `serverInternal` carrying the CA's own
message, typically `Denied by Policy Module` with the explanation that the
public key does not meet the template's minimum size, and the order becomes
invalid.
cert-manager then waits before trying again, starting at an hour and doubling up
to 32 hours. Fix the key settings, then run `cmctl renew <certificate>` to retry
at once.

## Trusting issued certificates in pods

The Secret cert-manager writes holds `tls.crt` and `tls.key`. The server returns
the leaf, the issuing CA and the root, and cert-manager keeps what it downloads,
so `tls.crt` carries that whole chain. The ACME issuer never writes `ca.crt`, so
an application that insists on one has to be given the root another way.

Anything that connects to these workloads has to trust your ADCS root. Windows
machines in the domain already do. Inside the cluster you distribute the root
yourself:

- **A ConfigMap.** Put the root PEM in a ConfigMap in each namespace that needs
  it and mount it beside the certificate, for example with a projected volume
  that presents `tls.crt`, `tls.key` and the root in one directory. It needs no
  extra component, but keeping the copies current is up to you.
- **trust-manager.** cert-manager's companion project copies one bundle into
  every namespace, or into the namespaces a label selects. Its `Bundle` API is
  still `v1alpha1`, so follow its documentation for the release you install.

## Renewal and ARI

cert-manager renews at two thirds of the certificate's actual lifetime unless
you set `renewBefore` or `renewBeforePercentage`, and the lifetime is whatever
the template gave the certificate. Since cert-manager 1.18, every renewal
generates a new private key, because `rotationPolicy` defaults to `Always`.

The server advertises ACME Renewal Information (ARI), which lets it tell a
client when to renew; see [renewal timing](acme-clients.md#renewal-timing-ari).
Its suggested window sits at about the same two thirds point, so on an ordinary
day ARI changes nothing for cert-manager. It matters after a revocation: a
revoked certificate's window moves into the past, and a client that reads ARI
renews at once.

cert-manager reads ARI only from release 1.21, and only with the `ACMEUseARI`
feature gate switched on for the controller. The gate is alpha and off by
default, so out of the box cert-manager renews on its own schedule, and a
revocation does not reach the cluster until the next scheduled renewal. The
gate goes in the controller's feature gates, for example this Helm value:

```yaml
config:
  featureGates:
    ACMEUseARI: true
```

**Not yet run against Ducks in a Row:** renewal, and ARI with cert-manager.

The server limits requests per source address, and a cluster usually reaches it
through one address, so every Issuer in it shares one budget. A burst of new
certificates can be refused with `rateLimited`; see
[rate limits partition per source address](configuration.md#rate-limits-partition-per-source-address).

## OpenShift

Nothing on this page has been run on OpenShift, and nothing about OpenShift
itself has been verified against Ducks in a Row. The Issuer and Certificate
above are standard cert-manager resources, and Red Hat ships cert-manager as
the cert-manager Operator for Red Hat OpenShift; see Red Hat's
[documentation for the operator](https://docs.redhat.com/en/documentation/openshift_container_platform/4.19/html/security_and_compliance/cert-manager-operator-for-red-hat-openshift).
Two points are documented upstream and have not been run here:

- **HTTP-01 through the built in router.** Since cert-manager 1.18, the solver's
  temporary Ingress uses `pathType: Exact`. OpenShift converts an Ingress into a
  Route for its router and skips a path of that type, so the challenge URL is
  never served and the challenge fails with a 503. cert-manager's
  [compatibility notes](https://cert-manager.io/docs/installation/compatibility/)
  give the fix, switching off the `ACMEHTTP01IngressPathTypeExact` feature gate,
  and say the Red Hat operator has had that gate off by default since its 1.18.0
  release. Documented upstream, not run here.
- **Routes.** cert-manager itself does not act on OpenShift Routes. The separate
  [openshift-routes](https://github.com/cert-manager/openshift-routes) project
  issues certificates for Routes from any cert-manager issuer, and warns that it
  is not designed for clusters shared between tenants. Documented upstream, not
  run here.

## Troubleshooting

| Symptom | Likely cause | What to do |
|---|---|---|
| The Issuer never becomes ready: `x509: certificate signed by unknown authority` | cert-manager does not trust your root | Set `caBundle`; see [trusting the ACME endpoint](#trusting-the-acme-endpoint) |
| `x509: certificate relies on legacy Common Name field`, or a SHA-1 complaint | The server's certificate names its host only in the common name, or the chain is signed with SHA-1 | Let the server enrol its own certificate, and move the CA to SHA-256 |
| `externalAccountRequired` | The mode is Required and the Issuer has no binding | Add `externalAccountBinding` and the secret |
| `failed to decode external account binding key data` | The secret is not base64url, for example standard base64 with `+`, `/` or `=` in it | Store the key exactly as the dashboard shows it |
| 403 `unauthorized`: `External account binding signature verification failed.` | The key cert-manager holds is not the one issued: encoded a second time, stored with a trailing newline, or from before a regenerate | Recreate the secret from the key as shown, with `--from-literal`; see [the EAB secret](#the-eab-secret) |
| 403 `unauthorized` naming a credential | The credential is revoked, expired, or cannot be decrypted on this server | See [troubleshooting](troubleshooting.md#registration-or-ordering-fails-with-403-unauthorized-naming-a-credential) |
| `rejectedIdentifier` | A name is outside the allowed domain list or the credential's domain namespace | Add the domain, or order within the namespace |
| 403 "not enabled for ACME" | The template is not enabled for ACME | Enable it in the setup wizard, or point the Issuer at one that is |
| `serverInternal` with `Denied by Policy Module` | The key does not suit the template | Match `privateKey` to the template; see [key type](#key-type) |
| A challenge stays pending and the server log shows no attempt | cert-manager's own check cannot fetch the token, often because the cluster cannot resolve the name | Make the zone resolvable in the cluster, or use `waitInsteadOfSelfCheck` |
| cert-manager keeps waiting after it accepted the challenge, then reports a timeout | The server's HTTP-01 attempt failed | Read the reason in the server log, fix it, then `cmctl renew`; see below |
| `rateLimited` | Many certificates at once through one source address | Retry later, or see [rate limits](configuration.md#rate-limits-partition-per-source-address) |

**A failed HTTP-01 check can look like waiting.** This is read from the server's
code and cert-manager's, and has not been run. When the server's HTTP-01 attempt
fails, the server marks that challenge invalid, but it leaves the authorization
pending while the other challenges it offered for the same name, DNS-01 and
TLS-ALPN-01, are still unanswered. cert-manager waits on the authorization, not
the challenge, for up to two minutes at a time, so it can report a timeout
rather than the reason. The reason is in the server's log, in a warning of the
form `Challenge <id> (http-01) for <name> failed: <reason>`, where the reason is
something like a refused connection or `server returned HTTP 308`.
