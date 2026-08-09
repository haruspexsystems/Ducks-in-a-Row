import type { ReactNode } from 'react';
import { Link } from 'react-router-dom';
import { ArrowDown, ArrowUp, ArrowUpDown } from 'lucide-react';
import type { CertificateSummary } from '@/types';
import { certificateDisplayName, formatDate, daysUntilExpiry, getExpiryState, isRevoked, revocationReasonLabel, hasCertificate } from '@/types';
import { StatusBadge, ExpiryBadge, RenewalBadge, ReplacedBadge } from './StatusBadge';
import { useExpiryWarningDays } from '@/hooks/useExpiryWarningDays';

interface CertificateTableProps {
  certificates: CertificateSummary[];
  sortBy?: string;
  sortDesc?: boolean;
  onSort: (column: string) => void;
  isLoading?: boolean;
  /**
   * What to render when there are no rows (issue #157). The page owns the
   * decision, because only it knows whether the inventory is empty or the
   * filters excluded everything; the table only owns the layout. The
   * fallback keeps the old wording for a caller that passes nothing.
   */
  emptyState?: ReactNode;
}

interface ColumnDef {
  key: string;
  label: string;
  sortable: boolean;
}

const columns: ColumnDef[] = [
  { key: 'subject', label: 'Subject', sortable: true },
  { key: 'template', label: 'Template', sortable: true },
  { key: 'serialNumber', label: 'Serial', sortable: false },
  { key: 'status', label: 'Status', sortable: true },
  // Issued is the certificate's NotBefore; the backend lowercases the sort key
  // into its existing notbefore arm, exactly as notAfter reaches notafter.
  { key: 'notBefore', label: 'Issued', sortable: true },
  { key: 'notAfter', label: 'Expires', sortable: true },
  // Key, label, and cell all name the same fact. The "-or" against the label's
  // "-er" is deliberate: Requestor is the entity property, the DTO field, and
  // the sort key on the wire, while "CA Requester" is the wording the detail
  // page already uses for it.
  { key: 'requestor', label: 'CA Requester', sortable: true },
];

function SortIcon({ column, sortBy, sortDesc }: { column: string; sortBy?: string; sortDesc?: boolean }) {
  if (sortBy !== column) return <ArrowUpDown className="h-3.5 w-3.5 text-faint" />;
  return sortDesc
    ? <ArrowDown className="h-3.5 w-3.5 text-certus-600" />
    : <ArrowUp className="h-3.5 w-3.5 text-certus-600" />;
}

function ExpiryCell({ cert }: { cert: CertificateSummary }) {
  // Called before the early returns below, as the rules of hooks require.
  // React Query dedupes on the key, so this is one request for the whole table
  // rather than one per row.
  const warningDays = useExpiryWarningDays();

  // Pending, denied, and failed rows are requests that never produced a
  // certificate. Their validity dates are placeholders, so any countdown would
  // read as expired hundreds of thousands of days ago. These rows only reach
  // the table when the status filter asks for them.
  if (!hasCertificate(cert)) {
    return <span className="text-sm text-faint">—</span>;
  }

  // A revoked certificate's expiry countdown is noise; show when and why it
  // was revoked instead. Rows synced before the revocation columns existed
  // may lack the date until the next sync backfills it.
  if (isRevoked(cert)) {
    const reason = revocationReasonLabel(cert.revokedReason);
    return (
      <div>
        <div className="text-sm">
          {cert.revokedAt ? `Revoked ${formatDate(cert.revokedAt)}` : 'Revoked'}
        </div>
        {reason && <div className="text-xs text-muted">{reason}</div>}
      </div>
    );
  }

  const { notAfter } = cert;
  const days = daysUntilExpiry(notAfter);
  const dateStr = formatDate(notAfter);

  // The colour comes from getExpiryState so this cell, the badge beside it, and
  // the dashboard counts all cut over at the operator's configured window
  // (issue #152). daysUntilExpiry still supplies the number for the label.
  const state = getExpiryState(notAfter, warningDays);
  const daysLabel = days < 0 ? `${Math.abs(days)}d ago` : `${days}d left`;
  const daysClass =
    state === 'expired' ? 'text-red-600'
    : state === 'expiring-soon' ? 'text-amber-600'
    : 'text-muted';

  return (
    <div>
      <div className="text-sm">{dateStr}</div>
      <div className={`text-xs ${daysClass}`}>{daysLabel}</div>
    </div>
  );
}

export function CertificateTable({
  certificates,
  sortBy,
  sortDesc,
  onSort,
  isLoading,
  emptyState,
}: CertificateTableProps) {
  return (
    <div className="overflow-x-auto rounded-lg border border-hairline bg-surface">
      <table className="min-w-full divide-y divide-hairline">
        <thead className="bg-sunken">
          <tr>
            {columns.map((col) => (
              <th
                key={col.key}
                scope="col"
                aria-sort={
                  col.sortable && sortBy === col.key
                    ? (sortDesc ? 'descending' : 'ascending')
                    : undefined
                }
                className="px-4 py-3 text-left text-xs font-semibold text-ink-mid uppercase tracking-wider"
              >
                {col.sortable ? (
                  <button
                    type="button"
                    onClick={() => onSort(col.key)}
                    className="flex items-center gap-1.5 select-none rounded hover:text-ink focus:outline-none focus-visible:ring-2 focus-visible:ring-certus-500"
                  >
                    {col.label}
                    <SortIcon column={col.key} sortBy={sortBy} sortDesc={sortDesc} />
                  </button>
                ) : (
                  <div className="flex items-center gap-1.5">{col.label}</div>
                )}
              </th>
            ))}
          </tr>
        </thead>
        <tbody className="divide-y divide-hairline-soft">
          {isLoading && certificates.length === 0 ? (
            <tr>
              <td colSpan={columns.length} className="px-4 py-12 text-center text-faint">
                Loading certificates...
              </td>
            </tr>
          ) : certificates.length === 0 ? (
            <tr>
              <td colSpan={columns.length} className="px-4 py-12 text-center text-faint">
                {emptyState ?? 'No certificates found'}
              </td>
            </tr>
          ) : (
            certificates.map((cert) => (
              <tr
                key={cert.id}
                className="hover:bg-sunken transition-colors"
              >
                <td className="px-4 py-3">
                  <Link
                    to={`/certificates/${cert.id}`}
                    className="text-sm font-medium text-certus-700 dark:text-certus-300 hover:text-certus-900 dark:text-certus-200 hover:underline"
                  >
                    {certificateDisplayName(cert)}
                  </Link>
                  {/*
                    Whether anything is renewing this certificate. Suppressed on
                    pending, denied, and failed rows: those are requests that
                    never became certificates, and an ACME order still waiting at
                    the CA has no ACME certificate row yet, so it would render as
                    manual while it is nothing of the sort.
                  */}
                  {hasCertificate(cert) && (
                    <div className="mt-1">
                      <RenewalBadge issuedByAcme={cert.issuedByAcme} />
                    </div>
                  )}
                  {cert.subjectAlternativeNames && (
                    <div className="text-xs text-faint mt-0.5 truncate max-w-xs">
                      SANs: {cert.subjectAlternativeNames}
                    </div>
                  )}
                </td>
                <td className="px-4 py-3">
                  <span className="inline-flex items-center px-2 py-0.5 rounded bg-sunken-strong text-xs font-medium text-ink-soft">
                    {cert.templateName}
                  </span>
                </td>
                <td className="px-4 py-3 text-sm text-muted font-mono text-xs">
                  {cert.serialNumber || '—'}
                </td>
                <td className="px-4 py-3">
                  <div className="flex items-center gap-1.5">
                    <StatusBadge status={cert.status} />
                    {hasCertificate(cert) && !isRevoked(cert) && (
                      <ExpiryBadge notAfter={cert.notAfter} />
                    )}
                    {/*
                      Annotation, never a filter: the issue is explicit that a
                      superseded row stays in the list and simply says so.
                    */}
                    <ReplacedBadge supersededById={cert.supersededById} />
                  </div>
                </td>
                {/*
                  Issued is the certificate's NotBefore. Requests that never
                  produced a certificate carry placeholder dates, so this cell
                  shows the same dash the serial and expiry cells use.
                */}
                <td className="px-4 py-3 text-sm text-muted">
                  {hasCertificate(cert) ? formatDate(cert.notBefore) : '—'}
                </td>
                <td className="px-4 py-3">
                  <ExpiryCell cert={cert} />
                </td>
                {/*
                  The CA's own record of who submitted the request, which every
                  certificate carries. This cell used to render the ACME contact
                  email under a key that said requestor, so it was blank for the
                  majority of certificates a real CA holds (issue #156). The ACME
                  contact keeps its place on the detail page, beside this field.

                  Absent reads as an em dash, matching the serial and expiry
                  cells rather than the detail page's "Unknown". In a dense grid
                  the header supplies the noun, and a third glyph for absence
                  inside one table would be the confusion this issue removes.
                */}
                <td className="px-4 py-3 text-sm text-muted">
                  {cert.requestor ?? '—'}
                </td>
              </tr>
            ))
          )}
        </tbody>
      </table>
    </div>
  );
}
