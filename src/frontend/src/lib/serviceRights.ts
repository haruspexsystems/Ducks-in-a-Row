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
 * True for a row whose right this server never uses: in monitor mode, a right
 * only issuance or revocation needs (issue #470). The page shows it as not
 * needed, never as a failure, so nobody is sent to ask for it.
 */
export function isNotNeeded(row: ServiceRightsRow): boolean {
  return row.notNeeded === 'monitorMode';
}

/**
 * How one row is shown. A row not needed in this mode reads as such whatever
 * its status; otherwise the status decides.
 */
export function rowPresentation(row: ServiceRightsRow): StatusPresentation {
  if (isNotNeeded(row)) return { label: 'Not needed in monitor mode', tone: 'skipped' };
  return statusPresentation(row.status);
}

/**
 * The wording for a row. A failed optional row says so: Issue and Manage
 * Certificates is only for revocation, so "Failed" alone would read as more
 * alarming than it is.
 */
export function statusLabel(row: ServiceRightsRow): string {
  if (isNotNeeded(row)) return rowPresentation(row).label;
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

/**
 * The Settings card's line about templates the check left out (issue #478), or
 * null when it left none out. Those templates have no rows, so without this line
 * their absence reads as a clean answer. The count is of the names the status file
 * records, so a template recorded under both of its names can be counted although
 * it has a row; it can say too many, never too few. Written as "not above zero"
 * so a payload without the field shows nothing rather than a broken sentence.
 */
export function templatesNotCheckedText(report: ServiceRightsReport): string | null {
  const count = report.templatesNotChecked;
  if (!(count > 0)) return null;
  // Monitor mode needs no Enroll at all, which the template rows above already say,
  // so the line must not read as an open question. A server switched from full mode
  // keeps the templates it had, which is how a monitor mode check finds any.
  if (report.rows.some(isNotNeeded)) {
    return count === 1
      ? '1 more template enabled for ACME was not checked, because one check reads a limited number of templates. Monitor mode needs no Enroll on it, so this matters only after a switch to full mode.'
      : `${count} more templates enabled for ACME were not checked, because one check reads a limited number of templates. Monitor mode needs no Enroll on them, so this matters only after a switch to full mode.`;
  }
  return count === 1
    ? '1 more template enabled for ACME was not checked, because one check reads a limited number of templates. Nothing above says whether this server holds Enroll on it.'
    : `${count} more templates enabled for ACME were not checked, because one check reads a limited number of templates. Nothing above says whether this server holds Enroll on them.`;
}

/**
 * Every row that is not Proven and that this server needs, which is what the
 * acknowledgement names. A right monitor mode never uses is not something to
 * acknowledge going without.
 */
export function rowsNotProven(report: ServiceRightsReport): ServiceRightsRow[] {
  return report.rows.filter((r) => r.status !== 'proven' && !isNotNeeded(r));
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
  return report.rows.some((r) => !isNotNeeded(r) && (r.status === 'unproven' || r.status === 'failed'));
}
