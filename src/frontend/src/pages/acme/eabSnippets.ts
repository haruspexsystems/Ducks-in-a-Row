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
 * issues secrets for.
 */

/** Shown in place of the secret once it can no longer be displayed. */
export const SECRET_PLACEHOLDER = '<PASTE-SAVED-SECRET>';

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
 */
export function buildEabSnippets(
  directoryUrl: string,
  kid: string,
  secret: string,
): EabSnippet[] {
  return [
    {
      id: 'certbot',
      client: 'certbot',
      filename: 'certbot-eab.sh',
      text: `# certbot: the EAB flags are needed once, when the account is created.
# HTTP-01 with certbot answering on port 80 itself. The default Web
# Server ACME template issues RSA, so request an RSA key.
certbot certonly --standalone \\
  --server ${directoryUrl} \\
  --eab-kid ${kid} \\
  --eab-hmac-key '${secret}' \\
  --email you@example.com \\
  -d host.corp.example.com \\
  --key-type rsa --rsa-key-size 2048
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

# acme.sh defaults to an EC key; the default Web Server ACME template
# issues RSA, so pass --keylength 2048.
acme.sh --issue --standalone \\
  --server ${directoryUrl} \\
  -d host.corp.example.com \\
  --keylength 2048
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
      text: `# cert-manager: store the MAC key as a secret, then apply this issuer.
# The key is already base64url encoded, store it as it is. Run the
# kubectl line, then delete it from this file before committing the
# manifest anywhere; the whole point of keySecretRef is that the
# manifest itself carries no secret.
#
#   kubectl create secret generic ducks-eab --from-literal=secret='${secret}'
#
apiVersion: cert-manager.io/v1
kind: Issuer
metadata:
  name: ducks-in-a-row
spec:
  acme:
    server: ${directoryUrl}
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
	# The default Web Server ACME template issues RSA; Caddy defaults
	# to an EC key, so pick RSA here.
	key_type rsa2048
	email you@example.com
}

host.corp.example.com {
	respond "Hello from Caddy"
}
`,
    },
  ];
}
