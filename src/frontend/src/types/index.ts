/** Certificate summary returned by the list endpoint. */
export interface CertificateSummary {
  id: number;
  requestId: number;
  serialNumber: string;
  subject: string;
  subjectAlternativeNames?: string;
  templateName: string;
  notBefore: string;
  notAfter: string;
  status: string;
  requestor?: string;
  requestDate: string;
  revokedAt?: string;
  revokedReason?: number;
  /** Contact email of the ACME account that requested this certificate, when known. */
  acmeContactEmail?: string;
  /**
   * Whether Ducks issued this certificate through the ACME proxy. True is good
   * evidence that an ACME client is renewing it, not proof that the client is
   * still running. False means the certificate reached the inventory from the
   * CA database only, so nothing in Ducks renews it.
   *
   * Not derivable from acmeContactEmail, which is null on a certificate Ducks
   * did issue whenever the ACME account carries no mailto contact.
   */
  issuedByAcme: boolean;
  /**
   * Id of the later certificate that appears to have replaced this one, when
   * there is one. Ducks infers this from the template and the certificate's
   * names; the CA does not record renewals and never reports it. Present on the
   * list response because badging a superseded row is the point, and a page of
   * 25 rows could never work the answer out for itself.
   *
   * Annotation only. It is not a filter, not a sort key, and not a count, and
   * `CertificateQuery` deliberately has no matching parameter.
   */
  supersededById?: number;
}

/**
 * One end of an inferred supersession relationship, carried on the detail
 * response so the page can name the other certificate and show the evidence.
 *
 * `requestor` is part of that evidence: two teams asking the same template for
 * the same hostname is indistinguishable from a renewal by names alone, and two
 * different requesters is how a reader catches it.
 */
export interface CertificateLink {
  id: number;
  subject: string;
  subjectAlternativeNames?: string;
  serialNumber: string;
  notBefore: string;
  notAfter: string;
  status: string;
  requestor?: string;
}

/** Full certificate detail (returned by the single-cert endpoint). */
export interface CertificateDetail extends CertificateSummary {
  firstSyncedAt: string;
  lastSyncedAt: string;
  /**
   * The CA's own explanation of what happened to the request, verbatim. Only
   * present on Pending, Denied, and Failed rows. Rendered as text attributed to
   * the CA and never reworded. Detail endpoint only: it mirrors the server DTO,
   * where keeping CA authored text off the list response is deliberate.
   */
  dispositionMessage?: string;
  /** The HRESULT the CA recorded. Signed; format unsigned for display. */
  statusCode?: number;
  /** The certificate that appears to have replaced this one, resolved. */
  supersededBy?: CertificateLink;
  /**
   * The certificates this one appears to have replaced. Usually empty or one.
   * More than one is possible and correct: a revoked certificate never
   * supersedes, so one sitting between two issued certificates leaves both it
   * and its own predecessor pointing at the same successor.
   */
  supersedes?: CertificateLink[];

  /*
   * Cryptographic detail read from the certificate's own DER. Detail endpoint
   * only, mirroring the server DTO: none of it may become a list column, a
   * filter, a sort key, or a count. Inventory by key algorithm is the paid
   * Compliance tier feature; one certificate's key detail on its own page is
   * what any certificate viewer shows.
   *
   * Every one is optional because a row whose certificate blob was unavailable
   * carries none of them, and because a certificate need not have an EKU or a
   * key usage extension at all. Values arrive as the codes the certificate
   * carries, never as resolved names, so no CA host's Windows locale can leak
   * into the display. The label maps below resolve them.
   */

  /** Short token for the public key algorithm ("RSA", "ECDSA"), or a raw OID. */
  keyAlgorithm?: string;
  /** Key size in bits, absent for an algorithm with no such measure. */
  keySizeBits?: number;
  /** The signature algorithm OID; label with signatureAlgorithmLabel. */
  signatureAlgorithmOid?: string;
  /** Uppercase hex SHA-256 thumbprint, unseparated, not the SHA-1 one. */
  sha256Thumbprint?: string;
  /** EKU OIDs in certificate order, comma separated. */
  extendedKeyUsageOids?: string;
  /** The raw .NET X509KeyUsageFlags bit field; decode with keyUsageLabels. */
  keyUsage?: number;

  /**
   * Whether the download endpoints have a certificate to serve. False on a
   * request that never became a certificate, and on a row synced before the
   * DER was captured, which the next sync fixes.
   */
  canDownload: boolean;

  /**
   * Why the revoke action is unavailable: "guardrail" when the TLS
   * capability ceiling refuses the certificate, "out-of-scope" when the
   * configured revocation scope does not cover it. Absent when revocation
   * is available, or when the row is not revocable at all (not Issued, or
   * no serial), where the button does not render in the first place.
   */
  revocationBlocked?: 'guardrail' | 'out-of-scope';
  /**
   * The sentence behind revocationBlocked, the same text the revoke
   * endpoint returns as its 403 problem detail.
   */
  revocationBlockedDetail?: string;
}

/** Paginated result wrapper. */
export interface PagedResult<T> {
  items: T[];
  totalCount: number;
  skip: number;
  take: number;
  hasMore: boolean;
}

/** Dashboard summary statistics. */
export interface CertificateStats {
  totalCertificates: number;
  issuedCertificates: number;
  expiringSoon: number;
  expired: number;
  revokedCertificates: number;
}

/** ADCS certificate template. */
export interface CertificateTemplate {
  name: string;
  displayName: string;
  oid: string;
  /** Whether the template's EKU metadata could be read from AD. */
  ekuVerified?: boolean;
  /**
   * The TLS guardrail's verdict on the template's verified metadata: false
   * means its certificates could never be issued or revoked through Ducks,
   * null or absent means unverified (the leaf check still decides at
   * issuance).
   */
  tlsCapable?: boolean | null;
  /** The guardrail's sentence when tlsCapable is false. */
  tlsBlockedReason?: string | null;
}

/**
 * The four certificate lifecycle states the list chips and the dashboard stat
 * cards both name (issue #155). Sent to the API as a symbolic name rather than
 * a pair of timestamps, so the server settles "now" and the operator's warning
 * window: a shared or bookmarked link still means what it said when it was
 * made, and it follows a later change to the alert threshold.
 */
export type CertificateState = 'valid' | 'expiring' | 'expired' | 'revoked';

/** The states in the order the chips present them, and the guard for the URL. */
export const CERTIFICATE_STATES: readonly CertificateState[] = [
  'valid',
  'expiring',
  'expired',
  'revoked',
];

/** Narrow an untrusted string (a hand edited URL) to a known state. */
export function parseCertificateState(value: string | null): CertificateState | undefined {
  return CERTIFICATE_STATES.includes(value as CertificateState)
    ? (value as CertificateState)
    : undefined;
}

/** Query parameters for the certificate list endpoint. */
export interface CertificateQuery {
  search?: string;
  template?: string;
  status?: string;
  state?: CertificateState;
  expiringBefore?: string;
  expiringAfter?: string;
  sortBy?: string;
  sortDesc?: boolean;
  skip?: number;
  take?: number;
}

/** Certificate status enum for UI rendering. */
export type CertStatus = 'Issued' | 'Revoked' | 'Pending' | 'Denied' | 'Failed';

/** Computed expiry state for visual indicators. */
export type ExpiryState = 'valid' | 'expiring-soon' | 'expired';

/**
 * Compute the expiry state from a notAfter date string.
 *
 * warningDays is required on purpose (issue #152): a default here is how three
 * surfaces each ended up hardcoding 30 days while the operator's configured
 * alert threshold said something else. Callers take it from
 * useExpiryWarningDays(), and the compiler now proves none of them can quietly
 * fall back to a literal.
 */
export function getExpiryState(notAfter: string, warningDays: number): ExpiryState {
  const expiry = new Date(notAfter);
  const now = new Date();
  const diffMs = expiry.getTime() - now.getTime();
  const diffDays = diffMs / (1000 * 60 * 60 * 24);

  if (diffDays < 0) return 'expired';
  if (diffDays < warningDays) return 'expiring-soon';
  return 'valid';
}

/** Format a date string for display. */
export function formatDate(dateStr: string): string {
  return new Date(dateStr).toLocaleDateString('en-US', {
    year: 'numeric',
    month: 'short',
    day: 'numeric',
  });
}

/** Format a date string with time. */
export function formatDateTime(dateStr: string): string {
  return new Date(dateStr).toLocaleString('en-US', {
    year: 'numeric',
    month: 'short',
    day: 'numeric',
    hour: '2-digit',
    minute: '2-digit',
  });
}

/**
 * Compact relative time ("just now", "5m ago", "3h ago"). Returns an empty
 * string for an unparseable input, so a caller never renders a fabricated
 * time. Promoted from the dashboard activity feed for the header sync
 * context (issue #157).
 */
export function relativeTime(iso: string): string {
  const then = Date.parse(iso);
  if (Number.isNaN(then)) return '';
  const minutes = Math.round((Date.now() - then) / 60_000);
  if (minutes < 1) return 'just now';
  if (minutes < 60) return `${minutes}m ago`;
  const hours = Math.round(minutes / 60);
  if (hours < 24) return `${hours}h ago`;
  const days = Math.round(hours / 24);
  if (days === 1) return 'Yesterday';
  if (days < 7) return `${days}d ago`;
  return new Date(then).toLocaleDateString();
}

/** CRL revocation reason labels (RFC 5280 5.3.1; code 7 is unused). */
const REVOCATION_REASONS: Record<number, string> = {
  0: 'Unspecified',
  1: 'Key Compromise',
  2: 'CA Compromise',
  3: 'Affiliation Changed',
  4: 'Superseded',
  5: 'Cessation of Operation',
  6: 'Certificate Hold',
  8: 'Remove From CRL',
  9: 'Privilege Withdrawn',
  10: 'AA Compromise',
};

/**
 * The reasons the revoke dialog offers, in code order, derived from the map
 * above so the labels stay in one home (issue #159). Deliberately 0 to 6
 * only, and the server enforces the same set: 8 (Remove From CRL) un-revokes
 * a held certificate rather than revoking anything, and ADCS acceptance of
 * 9 and 10 is unverified, so they stay display only until a CA probe proves
 * them.
 */
export const REVOCATION_REASON_OPTIONS: ReadonlyArray<{ code: number; label: string }> =
  Object.entries(REVOCATION_REASONS)
    .map(([code, label]) => ({ code: Number(code), label }))
    .filter(({ code }) => code <= 6)
    .sort((a, b) => a.code - b.code);

/** Whether a certificate is revoked at the CA. Single home for the status string. */
export function isRevoked(cert: { status: string }): boolean {
  return cert.status === 'Revoked';
}

/**
 * Whether this row is a certificate rather than a request that never became
 * one. Pending, Denied, and Failed rows come from the CA's request table and
 * carry no serial number, no subject, and no validity period, so every expiry
 * affordance has to be suppressed for them. Single home for that distinction.
 */
export function hasCertificate(cert: { status: string }): boolean {
  return cert.status === 'Issued' || cert.status === 'Revoked';
}

/**
 * Tailwind classes for the CA disposition callout, keyed on status. Pending is
 * informational; Denied and Failed need attention.
 */
export function dispositionTone(status: string): {
  container: string;
  heading: string;
  body: string;
} {
  return status === 'Pending'
    ? {
        container: 'bg-amber-50 border-amber-200',
        heading: 'text-amber-900',
        body: 'text-amber-800',
      }
    : {
        container: 'bg-red-50 border-red-200',
        heading: 'text-red-900',
        body: 'text-red-800',
      };
}

/**
 * An HRESULT as the 0x8009xxxx form an admin can search for or pass to
 * `certutil -error`. The CA records it signed, so it is coerced back to
 * unsigned before formatting.
 */
export function formatHResult(code: number): string {
  return `0x${(code >>> 0).toString(16).toUpperCase().padStart(8, '0')}`;
}

/** Human label for a CRL reason code; undefined when there is no code. */
export function revocationReasonLabel(code?: number): string | undefined {
  return code == null ? undefined : REVOCATION_REASONS[code] ?? `Reason ${code}`;
}

/*
 * Display labels for the cryptographic detail the API returns as codes. The
 * split is deliberate and matches the revocation reason pattern above: the
 * database stores what the certificate carries, and the dashboard owns the
 * words. Resolving names server side would answer from the CA host's Windows
 * OID table, which is locale dependent, and bake that host's language into
 * every row.
 *
 * Every map falls back to the raw code rather than to "Unknown", so an OID we
 * have never seen still tells the admin something they can search for.
 */

/**
 * Extended key usage OIDs an ADCS estate actually issues, plus the standard
 * RFC 5280 set. Anything absent renders as its bare OID.
 */
const EXTENDED_KEY_USAGES: Record<string, string> = {
  '2.5.29.37.0': 'Any Purpose',
  '1.3.6.1.5.5.7.3.1': 'Server Authentication',
  '1.3.6.1.5.5.7.3.2': 'Client Authentication',
  '1.3.6.1.5.5.7.3.3': 'Code Signing',
  '1.3.6.1.5.5.7.3.4': 'Email Protection',
  '1.3.6.1.5.5.7.3.5': 'IPsec End System',
  '1.3.6.1.5.5.7.3.6': 'IPsec Tunnel',
  '1.3.6.1.5.5.7.3.7': 'IPsec User',
  '1.3.6.1.5.5.7.3.8': 'Time Stamping',
  '1.3.6.1.5.5.7.3.9': 'OCSP Signing',
  '1.3.6.1.5.2.3.5': 'KDC Authentication',
  '1.3.6.1.4.1.311.10.3.1': 'Microsoft Trust List Signing',
  '1.3.6.1.4.1.311.10.3.4': 'Encrypting File System',
  '1.3.6.1.4.1.311.10.3.4.1': 'File Recovery',
  '1.3.6.1.4.1.311.10.3.12': 'Document Signing',
  '1.3.6.1.4.1.311.20.2.1': 'Certificate Request Agent',
  '1.3.6.1.4.1.311.20.2.2': 'Smart Card Logon',
  '1.3.6.1.4.1.311.21.5': 'Private Key Archival',
  '1.3.6.1.4.1.311.21.6': 'Key Recovery Agent',
};

/**
 * Signature algorithm OIDs, labelled the way certutil prints them, because
 * comparing this page against certutil for the same certificate is exactly
 * what the field is for.
 */
const SIGNATURE_ALGORITHMS: Record<string, string> = {
  '1.2.840.113549.1.1.5': 'sha1RSA',
  '1.2.840.113549.1.1.10': 'RSASSA-PSS',
  '1.2.840.113549.1.1.11': 'sha256RSA',
  '1.2.840.113549.1.1.12': 'sha384RSA',
  '1.2.840.113549.1.1.13': 'sha512RSA',
  '1.2.840.10045.4.1': 'sha1ECDSA',
  '1.2.840.10045.4.3.2': 'sha256ECDSA',
  '1.2.840.10045.4.3.3': 'sha384ECDSA',
  '1.2.840.10045.4.3.4': 'sha512ECDSA',
  '1.3.101.112': 'Ed25519',
  '1.3.101.113': 'Ed448',
};

/**
 * Key usage bits, keyed by the .NET X509KeyUsageFlags values.
 *
 * These are NOT the RFC 5280 bit numbers, and the two run in opposite
 * directions: the RFC numbers digitalSignature as bit 0 and crlSign as bit 6,
 * while .NET gives DigitalSignature the value 128 and CrlSign the value 2. The
 * API persists `(int)X509KeyUsageExtension.KeyUsages`, so these are the values
 * that arrive here. Reading the RFC bit order into this map would mislabel
 * every flag on every certificate, and plausibly enough to go unnoticed.
 */
const KEY_USAGE_FLAGS: ReadonlyArray<[number, string]> = [
  [128, 'Digital Signature'],
  [64, 'Non-Repudiation'],
  [32, 'Key Encipherment'],
  [16, 'Data Encipherment'],
  [8, 'Key Agreement'],
  [4, 'Certificate Signing'],
  [2, 'CRL Signing'],
  [1, 'Encipher Only'],
  [32768, 'Decipher Only'],
];

/** Human label for a signature algorithm OID, falling back to the OID. */
export function signatureAlgorithmLabel(oid?: string): string | undefined {
  return oid == null ? undefined : SIGNATURE_ALGORITHMS[oid] ?? oid;
}

/** Human label for one EKU OID, falling back to the OID. */
export function extendedKeyUsageLabel(oid: string): string {
  return EXTENDED_KEY_USAGES[oid] ?? oid;
}

/**
 * The EKU list as name and OID pairs, in certificate order. Undefined when the
 * certificate carries no EKU extension, which means "no restriction" and is a
 * different thing from an empty list.
 */
export function extendedKeyUsages(
  oids?: string
): Array<{ oid: string; label: string }> | undefined {
  if (!oids) return undefined;
  const entries = oids
    .split(',')
    .map((oid) => oid.trim())
    .filter(Boolean)
    .map((oid) => ({ oid, label: extendedKeyUsageLabel(oid) }));
  return entries.length > 0 ? entries : undefined;
}

/**
 * The set flags in a key usage bit field, in the order the RFC lists them.
 * Undefined when there is no key usage extension. An unrecognised bit is
 * reported as its own value rather than dropped, so a certificate carrying
 * something we do not know about does not quietly render as fewer usages than
 * it has.
 */
export function keyUsageLabels(flags?: number): string[] | undefined {
  if (flags == null) return undefined;

  const labels = KEY_USAGE_FLAGS.filter(([bit]) => (flags & bit) !== 0).map(([, label]) => label);
  const known = KEY_USAGE_FLAGS.reduce((mask, [bit]) => mask | bit, 0);
  const leftover = flags & ~known;
  if (leftover !== 0) labels.push(`Unrecognised (0x${leftover.toString(16).toUpperCase()})`);

  return labels.length > 0 ? labels : undefined;
}

/**
 * NIST curve names by key size, for the three curves ADCS issues. This is an
 * inference from the size, because the DER parse stores the key size and not
 * the curve, and a non NIST curve of the same size would be labelled wrongly.
 * Kept because P-256 is what an admin recognises and what certutil shows; any
 * size outside this set falls through to the plain bit count.
 */
const ECDSA_CURVES: Record<number, string> = {
  256: 'P-256',
  384: 'P-384',
  521: 'P-521',
};

/**
 * The key as one phrase: "RSA 2048", "ECDSA P-256". Undefined when the
 * algorithm is unknown, so the caller omits the row rather than labelling an
 * empty value.
 */
export function keyDescription(algorithm?: string, sizeBits?: number): string | undefined {
  if (!algorithm) return undefined;
  if (sizeBits == null) return algorithm;

  if (algorithm === 'ECDSA') {
    const curve = ECDSA_CURVES[sizeBits];
    if (curve) return `ECDSA ${curve}`;
  }

  return `${algorithm} ${sizeBits}`;
}

/** Compute days until expiry (negative = already expired). */
export function daysUntilExpiry(notAfter: string): number {
  const expiry = new Date(notAfter);
  const now = new Date();
  return Math.ceil((expiry.getTime() - now.getTime()) / (1000 * 60 * 60 * 24));
}

/**
 * Extract the CN from a subject DN string, falling back to the whole subject.
 *
 * A deliberate mirror of DistinguishedNameParser in
 * src/Certus.Core/Adcs/DistinguishedNameParser.cs, which carries the full
 * reasoning. Keep the two in step: the same subject has to read the same way in
 * the activity feed, the inventory, and the lineage key, and a fourth answer is
 * exactly the defect issue #231 closed.
 *
 * Reading up to the first comma is what this used to do, and it cut a common
 * name carrying a quoted comma in half. A comma is legal inside a CN value, and
 * the encoders escape it rather than dropping it: Windows CertNameToStr wraps
 * the value in double quotes and doubles any quote inside it, and the RFC 4514
 * form puts a backslash in front of it.
 *
 * The fallback is reached often rather than rarely. A SAN only certificate is
 * stored with a bare name and no "CN=" at all, and that name is shown verbatim.
 */
export function extractCN(subject: string): string {
  if (!subject.trim()) return subject;

  let position = 0;
  while (position < subject.length) {
    const end = componentEnd(subject, position);
    const text = subject.slice(position, end).trim();
    position = end + 1;

    // No equals sign means this is not an attribute at all: the sanitizer's
    // truncation marker and a bare CA supplied name both arrive that way, and
    // both have to be skipped rather than misread as a value.
    const equals = valueStart(text);
    if (equals < 0) continue;
    if (text.slice(0, equals).trim().toUpperCase() !== 'CN') continue;

    // A "CN=" with nothing after it is skipped so a real one later in the same
    // subject is still found.
    const value = unescapeValue(text.slice(equals + 1));
    if (value.trim()) return value;
  }

  return subject;
}

/**
 * The index one past the end of the component starting at `start`: the next
 * separator that is neither quoted nor escaped, or the end of the subject.
 *
 * Comma and semicolon both separate relative distinguished names in the X.500
 * string form. Plus separates the parts of a multi-valued one, and counts here
 * too, because a CN sitting after one is still a CN.
 */
function componentEnd(subject: string, start: number): number {
  let quoted = false;
  for (let i = start; i < subject.length; i++) {
    const ch = subject[i];

    // A backslash escapes only outside quotes, and only in front of a character
    // RFC 4514 lets it escape. Inside a quoted value the only thing that is
    // special is the doubled quote. The isEscapable test must match the one in
    // unescapeValue, or the two disagree about where a component ends.
    if (ch === '\\' && !quoted && isEscapable(subject[i + 1])) {
      i++;
      continue;
    }

    if (ch === '"') {
      // A doubled quote inside a quoted value is one literal quote and does not
      // close it. That is how CertNameToStr writes a quote that was in the name.
      if (quoted && subject[i + 1] === '"') {
        i++;
        continue;
      }
      quoted = !quoted;
      continue;
    }

    if (!quoted && (ch === ',' || ch === ';' || ch === '+')) return i;
  }

  return subject.length;
}

/**
 * The index of the equals sign separating the attribute type from its value, or
 * -1 when the component carries none. Quote and escape aware for the same reason
 * the boundary scan is: an equals sign inside a value is part of the name.
 */
function valueStart(component: string): number {
  let quoted = false;
  for (let i = 0; i < component.length; i++) {
    const ch = component[i];

    if (ch === '\\' && !quoted && isEscapable(component[i + 1])) {
      i++;
      continue;
    }

    if (ch === '"') {
      if (quoted && component[i + 1] === '"') {
        i++;
        continue;
      }
      quoted = !quoted;
      continue;
    }

    if (!quoted && ch === '=') return i;
  }

  return -1;
}

/**
 * The decoded value: surrounding quotes removed, doubled quotes collapsed to
 * one, and backslash escapes resolved.
 *
 * Trimmed before decoding and not after, so a quoted value keeps whatever it
 * chose to keep. Quoting is how CertNameToStr preserves a leading or trailing
 * space in a name, and trimming afterwards would undo the reason for the quotes.
 */
function unescapeValue(raw: string): string {
  const value = raw.trim();
  if (!value) return '';

  let out = '';
  let quoted = false;

  for (let i = 0; i < value.length; i++) {
    const ch = value[i];

    if (ch === '\\' && !quoted && isEscapable(value[i + 1])) {
      out += value[i + 1];
      i++;
      continue;
    }

    if (ch === '"') {
      if (quoted && value[i + 1] === '"') {
        out += '"';
        i++;
        continue;
      }
      quoted = !quoted;
      continue;
    }

    out += ch;
  }

  return out;
}

/**
 * Whether a backslash in front of this character is an escape rather than two
 * literal characters. RFC 4514 section 3 lists exactly these. Declared optional
 * because every caller reads one character past the backslash and may be at the
 * end of the string, where there is nothing to escape.
 *
 * The restriction is load bearing, and the reason is that only one of the two
 * encoders escapes at all. CertNameToStr quotes instead, and it does not treat a
 * backslash as special in either direction: a name holding one is rendered with
 * the backslash intact and no quotes around it. So in the Windows form every
 * backslash is literal, and resolving the character after it unconditionally
 * rewrites names that were never escaped: "CORP\svc" read back as "CORPsvc".
 *
 * Hex escapes are not decoded at all, which this predicate enforces by leaving
 * the digits out. RFC 4514 does define the "\hh" byte form, but no encoder that
 * reaches this parser emits it, so decoding it served no real input and forged
 * names out of ones the certificate did carry: a requester may put the literal
 * text "\74\72\75\73\74\65\64" in a common name and Windows stores it verbatim.
 * Read as hex it spells "trusted".
 *
 * It also mangled any ordinary name whose backslash happened to be followed by
 * two hex digits, which "CORP\ab-server" is. That decoded to the single byte
 * 0xAB, which is not valid UTF-8 on its own, so the name came back as "CORP",
 * the replacement character, then "-server".
 *
 * Keep in step with IsEscapable in DistinguishedNameParser.cs.
 */
function isEscapable(ch: string | undefined): boolean {
  if (ch === undefined) return false;
  return ch === ',' || ch === '+' || ch === '"' || ch === '\\'
    || ch === '<' || ch === '>' || ch === ';' || ch === '=' || ch === '#' || ch === ' ';
}

/**
 * First subject alternative name from the stored comma separated list, with
 * the "dns:" / "ip:" label stripped. Display fallback for SAN only
 * certificates (typical for ACME), whose subject DN is empty.
 */
export function firstSan(sans?: string): string | undefined {
  const first = sans?.split(',')[0]?.trim();
  if (!first) return undefined;
  return first.replace(/^(dns|ip):/i, '');
}

/**
 * Display name for a certificate: subject CN, else the first SAN, else the CA
 * request number, else an em dash so the cell is never blank.
 *
 * The request number matters for pending, denied, and failed rows. Those come
 * from the CA's request table and the columns we read carry the issued
 * certificate's names, which are empty until issuance, so they would otherwise
 * all render identically as an em dash and an admin could not tell which stuck
 * request an explanation belonged to. The request ID is what the Certification
 * Authority console keys on, so it is the number an admin can act with.
 */
export function certificateDisplayName(cert: {
  subject: string;
  subjectAlternativeNames?: string;
  requestId?: number;
}): string {
  const named = extractCN(cert.subject) || firstSan(cert.subjectAlternativeNames);
  if (named) return named;
  return cert.requestId ? `Request ${cert.requestId}` : '—';
}
