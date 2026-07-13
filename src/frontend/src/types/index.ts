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
}

/** Full certificate detail (returned by the single-cert endpoint). */
export interface CertificateDetail extends CertificateSummary {
  firstSyncedAt: string;
  lastSyncedAt: string;
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
}

/** Query parameters for the certificate list endpoint. */
export interface CertificateQuery {
  search?: string;
  template?: string;
  status?: string;
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

/** Compute the expiry state from a notAfter date string. */
export function getExpiryState(notAfter: string, warningDays = 30): ExpiryState {
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

/** Whether a certificate is revoked at the CA. Single home for the status string. */
export function isRevoked(cert: { status: string }): boolean {
  return cert.status === 'Revoked';
}

/** Human label for a CRL reason code; undefined when there is no code. */
export function revocationReasonLabel(code?: number): string | undefined {
  return code == null ? undefined : REVOCATION_REASONS[code] ?? `Reason ${code}`;
}

/** Compute days until expiry (negative = already expired). */
export function daysUntilExpiry(notAfter: string): number {
  const expiry = new Date(notAfter);
  const now = new Date();
  return Math.ceil((expiry.getTime() - now.getTime()) / (1000 * 60 * 60 * 24));
}

/** Extract CN from a subject DN string. */
export function extractCN(subject: string): string {
  const match = subject.match(/CN=([^,]+)/i);
  return match ? match[1] : subject;
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
 * Display name for a certificate: subject CN, else the first SAN, else an em
 * dash so the cell is never blank.
 */
export function certificateDisplayName(cert: {
  subject: string;
  subjectAlternativeNames?: string;
}): string {
  return extractCN(cert.subject) || firstSan(cert.subjectAlternativeNames) || '—';
}
