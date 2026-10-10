import type {
  RightNeededFor,
  RightsGroup,
  RightsStatus,
  ServiceRightsReport,
  ServiceRightsRow,
} from '@/api/serviceRights';

/**
 * Pure helpers for the service rights check (issue #440), kept apart from the
 * components so the rules that decide what an operator must acknowledge are
 * unit tested rather than read off a screen.
 */

/** How a status is shown. The tone picks the icon and colour; Inferred is never the pass colour. */
export interface StatusPresentation {
  label: string;
  tone: 'pass' | 'reading' | 'unknown' | 'fail' | 'skipped';
}

const PRESENTATION: Record<RightsStatus, StatusPresentation> = {
  proven: { label: 'Proven', tone: 'pass' },
  inferred: { label: 'Inferred', tone: 'reading' },
  unproven: { label: 'Unproven', tone: 'unknown' },
  failed: { label: 'Failed', tone: 'fail' },
  skipped: { label: 'Skipped', tone: 'skipped' },
};

export function statusPresentation(status: RightsStatus): StatusPresentation {
  return PRESENTATION[status];
}

/**
 * The wording for a failed optional row. Issue and Manage Certificates is only
 * for revocation, so "Failed" alone would read as more alarming than it is.
 */
export function statusLabel(row: ServiceRightsRow): string {
  if (row.status === 'failed' && row.optional) return 'Not granted (optional)';
  return statusPresentation(row.status).label;
}

const NEEDED_FOR_TEXT: Record<RightNeededFor, string> = {
  issuance: 'issuance',
  inventory: 'the certificate inventory',
  revocation: 'revocation',
  crlWatching: 'CRL watching',
};

/** "Needed for issuance and CRL watching", in plain words. */
export function neededForText(neededFor: RightNeededFor[]): string {
  const words = neededFor.map((n) => NEEDED_FOR_TEXT[n]);
  if (words.length === 0) return '';
  if (words.length === 1) return `Needed for ${words[0]}`;
  return `Needed for ${words.slice(0, -1).join(', ')} and ${words[words.length - 1]}`;
}

/** The rows of the given groups, in the report's order. */
export function rowsIn(report: ServiceRightsReport, groups?: RightsGroup[]): ServiceRightsRow[] {
  return groups ? report.rows.filter((r) => groups.includes(r.group)) : report.rows;
}

/** Every row that is not Proven, which is what the acknowledgement names. */
export function rowsNotProven(report: ServiceRightsReport): ServiceRightsRow[] {
  return report.rows.filter((r) => r.status !== 'proven');
}

/**
 * True when a certificate this CA issued to this server was found: the one
 * exercise of Request Certificates and of a template's Enroll the wizard can
 * offer.
 */
export function hasEnrolmentEvidence(report: ServiceRightsReport): boolean {
  return report.rows.some((r) => r.id === 'https-enrolment' && r.status === 'proven');
}

/**
 * Whether completing setup needs an explicit acknowledgement (decision 4 on
 * issue #440). Never a block: the operator can always go on, but not without
 * being told what stays unproven. It is needed when no enrolment proves
 * anything and some row is Unproven or Failed, and also when the check itself
 * could not be loaded, because then nothing is known at all.
 */
export function needsAcknowledgement(report: ServiceRightsReport | null): boolean {
  if (report === null) return true;
  if (hasEnrolmentEvidence(report)) return false;
  return report.rows.some((r) => r.status === 'unproven' || r.status === 'failed');
}
