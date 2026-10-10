/**
 * Pure builders for the per client EAB setup snippets (issue #131). No
 * React and no fetch in here: the component hands in the directory URL,
 * key id, and secret (or the paste placeholder), and gets back ready to
 * render text, so the snippet content stays trivially testable and the
 * flag names live in exactly one place.
 *
 * Flag names verified against each client's current documentation on
 * 2026-07-16: certbot (--eab-kid, --eab-hmac-key), win-acme
 * (--eab-key-identifier, --eab-key), acme.sh (--eab-kid, --eab-hmac-key),
 * Posh-ACME (-ExtAcctKID, -ExtAcctHMACKey), cert-manager
 * (externalAccountBinding.keyID + keySecretRef), Caddy (acme_eab with
 * key_id and mac_key). All default to HS256, which is what this server
 * issues secrets for. cert-manager's caBundle and privateKey fields were
 * checked against its documentation for releases 1.20 and 1.21 on
 * 2026-09-27 (issue #439).
 */

import {
  acmeShKeyLength,
  caddyKeyType,
  certbotKeyFlags,
  certManagerPrivateKey,
  describeKeyRequirement,
  resolveTemplateKey,
  type TemplateKeyRequirement,
} from '@/lib/templateKey';

/** Shown in place of the secret once it can no longer be displayed. */
export const SECRET_PLACEHOLDER = '<PASTE-SAVED-SECRET>';

/**
 * Stands in for the CA root in the cert-manager manifest. The dashboard cannot
 * know which root the operator's cluster should trust, and it must not guess:
 * a value that is not base64 makes `kubectl apply` refuse the manifest, so a
 * placeholder left in place fails loudly instead of producing an issuer that
 * cannot reach this server.
 */
export const CA_BUNDLE_PLACEHOLDER = '<BASE64-OF-YOUR-CA-ROOT-PEM>';

/** One client's setup snippet. */
export interface EabSnippet {
  /** Stable identifier, also the selector key. */
  id: string;
  /** Display name for the client picker. */
  client: string;
  /** Suggested filename for the download button. */
  filename: string;
  /** The snippet body. */
  text: string;
}

/**
 * The directory URL for a template. The saved external URL is not
 * normalized, so trailing slashes are stripped to keep a double slash out
 * of the path (the same rule the setup wizard applies in ReviewStep and
 * ExternalUrlStep). The template segment is URL encoded because display
 * names with spaces are accepted, and an unencoded space would split the
 * pasted command in every shell.
 */
export function buildDirectoryUrl(externalUrl: string, template: string): string {
  return `${externalUrl.replace(/\/+$/, '')}/acme/${encodeURIComponent(template)}/directory`;
}

/**
 * The setup snippets for every supported client, in picker order. The
 * caller passes the real secret while it is on screen (the show once
 * panel) and SECRET_PLACEHOLDER afterwards, because the server never
 * returns a stored secret again.
 *
 * The key flags follow the selected template's own requirements rather than
 * assuming RSA. They used to be hardcoded to RSA 2048 with a comment saying
 * "the default Web Server ACME template issues RSA", which is a wrong command
 * on an EC template even when the server knows better (issue #213). Omitting
 * `key` keeps the RSA 2048 output, which is the right hedge when the template's
 * algorithm could not be read.
 */
export function buildEabSnippets(
  directoryUrl: string,
  kid: string,
  secret: string,
  key: TemplateKeyRequirement = resolveTemplateKey(null, null),
): EabSnippet[] {
  const keyNote = `# ${describeKeyRequirement(key)}`;
  const certbotFlags = certbotKeyFlags(key);
  const acmeShLength = acmeShKeyLength(key);
  const caddyType = caddyKeyType(key);
  const certManagerKey = certManagerPrivateKey(key);

  return [
    {
      id: 'certbot',
      client: 'certbot',
      filename: 'certbot-eab.sh',
      text: `# certbot: the EAB flags are needed once, when the account is created.
# HTTP-01 with certbot answering on port 80 itself.
${keyNote}
certbot certonly --standalone \\
  --server ${directoryUrl} \\
  --eab-kid ${kid} \\
  --eab-hmac-key '${secret}' \\
  --email you@example.com \\
${
  certbotFlags === null
    ? `  -d host.corp.example.com
# certbot cannot produce this key. Use acme.sh, which can.`
    : `  -d host.corp.example.com \\
  ${certbotFlags}`
}
`,
    },
    {
      id: 'win-acme',
      client: 'win-acme',
      filename: 'win-acme-eab.cmd',
      text: `rem win-acme: bind the account while creating the certificate.
rem --source iis reads the bindings of IIS site 1; see win-acme's
rem docs for manual or other sources.
wacs.exe --source iis --siteid 1 ^
  --baseuri ${directoryUrl} ^
  --eab-key-identifier ${kid} ^
  --eab-key "${secret}"
`,
    },
    {
      id: 'acme-sh',
      client: 'acme.sh',
      filename: 'acme-sh-eab.sh',
      text: `# acme.sh: register the account with the credential once, then order.
acme.sh --register-account \\
  --server ${directoryUrl} \\
  --eab-kid ${kid} \\
  --eab-hmac-key '${secret}'

${keyNote}
acme.sh --issue --standalone \\
  --server ${directoryUrl} \\
${
  acmeShLength === null
    ? `  -d host.corp.example.com
# acme.sh cannot produce this key; change the template's algorithm.`
    : `  -d host.corp.example.com \\
  --keylength ${acmeShLength}`
}
`,
    },
    {
      id: 'posh-acme',
      client: 'Posh-ACME',
      filename: 'posh-acme-eab.ps1',
      text: `Import-Module Posh-ACME

# Point Posh-ACME at the template directory, then bind the account.
Set-PAServer -DirectoryUrl ${directoryUrl}

New-PAAccount -Contact you@example.com -AcceptTOS \`
  -ExtAcctKID '${kid}' \`
  -ExtAcctHMACKey '${secret}'

New-PACertificate -Domain host.corp.example.com -Plugin WebRoot \`
  -PluginArgs @{ WebRootPath = 'C:\\inetpub\\wwwroot' }
`,
    },
    {
      id: 'cert-manager',
      client: 'cert-manager',
      filename: 'cert-manager-issuer.yaml',
      text: `# cert-manager: store the MAC key as a secret, then apply this file.
# The key is already base64url encoded, store it as it is. Run the
# kubectl line, then delete it from this file before committing the
# manifest anywhere; the whole point of keySecretRef is that the
# manifest itself carries no secret.
#
#   kubectl create secret generic ducks-eab --from-literal=secret='${secret}'
#
# An Issuer reads its secrets from its own namespace, so give that line
# and kubectl apply the same -n <namespace>. For a ClusterIssuer, change
# the Issuer's kind and the Certificate's issuerRef kind to ClusterIssuer,
# and create the secret in the cert-manager namespace instead.
#
# caBundle is the root certificate your ADCS chain ends in, as PEM,
# base64 encoded on one line, because cert-manager trusts only public
# roots unless told otherwise. That root is the right one once this
# server has enrolled its own certificate from your CA; while it still
# serves its self signed certificate, enrol one in the setup wizard.
#   Linux:      base64 -w0 corp-root.pem
#   PowerShell: [Convert]::ToBase64String([IO.File]::ReadAllBytes('corp-root.pem'))
# Remove the line only if this server's certificate is publicly trusted,
# and never set skipTLSVerify in its place.
apiVersion: cert-manager.io/v1
kind: Issuer
metadata:
  name: ducks-in-a-row
spec:
  acme:
    server: ${directoryUrl}
    caBundle: ${CA_BUNDLE_PLACEHOLDER}
    email: you@example.com
    privateKeySecretRef:
      name: ducks-account-key
    externalAccountBinding:
      keyID: ${kid}
      keySecretRef:
        name: ducks-eab
        key: secret
    solvers:
      - http01:
          ingress:
            ingressClassName: nginx
---
${keyNote}
# A certificate from this issuer. On an Ingress, the annotations
# cert-manager.io/issuer, cert-manager.io/private-key-algorithm and
# cert-manager.io/private-key-size do the same job.
apiVersion: cert-manager.io/v1
kind: Certificate
metadata:
  name: host-corp-example-com
spec:
  secretName: host-corp-example-com-tls
  dnsNames:
    - host.corp.example.com
  issuerRef:
    name: ducks-in-a-row
    kind: Issuer
${
  certManagerKey !== null
    ? `  privateKey:
    algorithm: ${certManagerKey.algorithm}
    size: ${certManagerKey.size}`
    : key.kind === 'unsupported'
      ? "  # cert-manager cannot produce this key; change the template's algorithm."
      : "  # cert-manager cannot produce an RSA key above 8192 bits; lower the template's minimum key size."
}
`,
    },
    {
      id: 'caddy',
      client: 'Caddy',
      filename: 'Caddyfile',
      text: `{
	acme_ca ${directoryUrl}
	acme_eab {
		key_id ${kid}
		mac_key ${secret}
	}
	${keyNote}
${
  caddyType === null
    ? '\t# Caddy cannot produce this key; change the template\'s algorithm.'
    : `\tkey_type ${caddyType}`
}
	email you@example.com
}

host.corp.example.com {
	respond "Hello from Caddy"
}
`,
    },
  ];
}
