/**
 * What key a template requires, derived from the viability the server reads
 * off the template's AD object, plus the client flags that ask for it.
 *
 * Pure, and the single place the frontend turns a `msPKI-Asymmetric-Algorithm`
 * value into a curve or a modulus size. Two surfaces render key flags (the
 * setup wizard's certbot example and the ACME tab's EAB snippets) and they
 * used to disagree: the wizard derived the curve from the template while the
 * snippets hardcoded RSA 2048, so an EC template got a wrong command on one of
 * them (issue #213).
 *
 * The server does the same derivation in `TlsCertificateEnroller.CreateKey`
 * for the key it generates itself. The two are deliberately kept in step; there
 * is no shared source of truth across the language boundary.
 */

/** The smallest RSA modulus current ADCS policy modules accept. */
export const MINIMUM_RSA_KEY_SIZE = 2048;

export type TemplateKeyKind = 'rsa' | 'ecdsa' | 'unknown' | 'unsupported';

export interface TemplateKeyRequirement {
  /**
   * `rsa` and `ecdsa` are verified requirements read from the template.
   * `unknown` means the algorithm could not be determined and callers should
   * hedge rather than assert; RSA is still the practical default, because the
   * stock templates are RSA. `unsupported` means the template names something
   * real that no ACME client here can be told to produce.
   */
  kind: TemplateKeyKind;
  /** The raw algorithm name as the template records it, for display. */
  algorithm: string | null;
  /** Modulus size for the RSA cases, never below {@link MINIMUM_RSA_KEY_SIZE}. */
  rsaKeySize: number;
  /** The NIST curve for the ECDSA case, else null. */
  curve: 'P-256' | 'P-384' | 'P-521' | null;
  /**
   * True when the template records an ECDH algorithm and this answers with the
   * ECDSA key on the same curve (issue #277). The commands are correct as
   * printed, so this is not a caveat about them; it flags that the template is
   * probably misconfigured and names the setting that fixes it.
   */
  substituted: boolean;
}

/**
 * Read a template's key requirement.
 *
 * The curve comes from the algorithm name's suffix (`ECDSA_P256` and friends),
 * falling back to the template minimum when the name carries no curve.
 *
 * An `ECDH_*` template resolves to the ECDSA key on the same curve, matching
 * `TlsCertificateEnroller.CreateKey` (issue #277). A PKCS#10 is self signed, so
 * no client can produce an encryption only key for it, and per RFC 5480 both
 * encode identically as `id-ecPublicKey` plus a named curve. So the curve is
 * the whole of what such a template constrains, and the printed commands are
 * right. `substituted` carries the fact onward, because the template is still
 * probably misconfigured.
 */
export function resolveTemplateKey(
  keyAlgorithm: string | null | undefined,
  minimalKeySize: number | null | undefined,
): TemplateKeyRequirement {
  const algorithm = keyAlgorithm?.trim() || null;
  const upper = algorithm?.toUpperCase() ?? null;

  // A template minimum below the floor is not honoured: the wizard used to
  // print the raw value, so a template recording 1024 produced a command that
  // asked for a 1024 bit key.
  const rsaKeySize = Math.max(MINIMUM_RSA_KEY_SIZE, minimalKeySize ?? MINIMUM_RSA_KEY_SIZE);

  if (upper === null) {
    return { kind: 'unknown', algorithm: null, rsaKeySize, curve: null, substituted: false };
  }
  if (upper === 'RSA') {
    return { kind: 'rsa', algorithm, rsaKeySize, curve: null, substituted: false };
  }

  // The two prefixes are disjoint, so neither test catches the other's names,
  // and a bare `DH` or `DSA` matches neither and stays unsupported.
  const substituted = upper.startsWith('ECDH');
  if (!substituted && !upper.startsWith('ECDSA')) {
    return { kind: 'unsupported', algorithm, rsaKeySize, curve: null, substituted: false };
  }

  const curve = upper.endsWith('P384')
    ? 'P-384'
    : upper.endsWith('P521')
      ? 'P-521'
      : upper.endsWith('P256')
        ? 'P-256'
        : (minimalKeySize ?? 256) >= 521
          ? 'P-521'
          : (minimalKeySize ?? 256) >= 384
            ? 'P-384'
            : 'P-256';

  return { kind: 'ecdsa', algorithm, rsaKeySize, curve, substituted };
}

/**
 * certbot's key flags, or null when certbot cannot be told to produce this
 * key: it has no P-521 curve, and it cannot produce a DSA or DH key at all.
 * A null answer means show the operator a note instead of a command.
 *
 * ECDH is not in that list. It resolves to the ECDSA key on the same curve,
 * which certbot produces perfectly well, and which is the only key anything
 * could put in a CSR for such a template (issue #277).
 */
export function certbotKeyFlags(key: TemplateKeyRequirement): string | null {
  if (key.kind === 'unsupported') return null;
  if (key.kind === 'ecdsa') {
    if (key.curve === 'P-521') return null;
    const curveParam = key.curve === 'P-384' ? 'secp384r1' : 'secp256r1';
    return `--key-type ecdsa --elliptic-curve ${curveParam}`;
  }
  // Both 'rsa' and 'unknown': the stock templates are RSA, so it is the right
  // command to hand over when nothing contradicts it.
  return `--key-type rsa --rsa-key-size ${key.rsaKeySize}`;
}

/**
 * acme.sh's `--keylength` value, or null when it cannot produce the key.
 * Unlike certbot, acme.sh does carry `ec-521`.
 */
export function acmeShKeyLength(key: TemplateKeyRequirement): string | null {
  if (key.kind === 'unsupported') return null;
  if (key.kind === 'ecdsa') {
    return key.curve === 'P-384' ? 'ec-384' : key.curve === 'P-521' ? 'ec-521' : 'ec-256';
  }
  return String(key.rsaKeySize);
}

/**
 * Caddy's `key_type` value, or null when Caddy cannot produce the key. Caddy
 * names only rsa2048, rsa4096, p256 and p384, so an RSA minimum between the
 * two sizes rounds up to the one that satisfies it, and P-521 has no value.
 */
export function caddyKeyType(key: TemplateKeyRequirement): string | null {
  if (key.kind === 'unsupported') return null;
  if (key.kind === 'ecdsa') {
    return key.curve === 'P-384' ? 'p384' : key.curve === 'P-521' ? null : 'p256';
  }
  return key.rsaKeySize > 2048 ? 'rsa4096' : 'rsa2048';
}

/** cert-manager's `Certificate.spec.privateKey` settings for a template. */
export interface CertManagerPrivateKey {
  algorithm: 'RSA' | 'ECDSA';
  size: number;
}

/** The only RSA sizes cert-manager accepts, smallest first. */
const CERT_MANAGER_RSA_SIZES = [2048, 4096, 8192];

/**
 * cert-manager's `privateKey` settings, or null when cert-manager cannot be
 * told to produce the key. It accepts RSA at 2048, 4096 and 8192 bits only, so
 * an RSA minimum between two of those rounds up to the next one (a 3072 bit
 * template gets 4096), and it names all three NIST curves by their size.
 *
 * cert-manager defaults to RSA 2048 when the setting is left out, so on an RSA
 * template the output only restates the default, and on an ECDSA template it
 * is the setting that keeps every order from being refused at finalize.
 */
export function certManagerPrivateKey(key: TemplateKeyRequirement): CertManagerPrivateKey | null {
  if (key.kind === 'unsupported') return null;
  if (key.kind === 'ecdsa') {
    return { algorithm: 'ECDSA', size: key.curve === 'P-384' ? 384 : key.curve === 'P-521' ? 521 : 256 };
  }
  const size = CERT_MANAGER_RSA_SIZES.find((s) => s >= key.rsaKeySize);
  return size === undefined ? null : { algorithm: 'RSA', size };
}

/**
 * One line naming what the template needs, for a comment at the head of a
 * generated snippet.
 */
export function describeKeyRequirement(key: TemplateKeyRequirement): string {
  switch (key.kind) {
    case 'ecdsa':
      // The command below it is correct either way, so lead with the curve and
      // let the ECDH note follow as the thing to go and fix.
      return key.substituted
        ? `This template requires curve ${key.curve} keys. It records ${key.algorithm}, ` +
            'which is an encryption only algorithm; set its Purpose to Signature in the ' +
            'Certificate Templates console to record ECDSA instead.'
        : `This template requires ECDSA keys on curve ${key.curve}.`;
    case 'rsa':
      return `This template requires RSA keys of at least ${key.rsaKeySize} bits.`;
    case 'unsupported':
      return `This template requires ${key.algorithm} keys, which this client cannot produce.`;
    default:
      return 'The template key algorithm could not be read, so this assumes RSA (the stock templates are RSA).';
  }
}
