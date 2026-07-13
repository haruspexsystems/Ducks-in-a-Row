import { Link } from 'react-router-dom';
import { ArrowDown, ArrowUp, ArrowUpDown } from 'lucide-react';
import type { CertificateSummary } from '@/types';
import { certificateDisplayName, formatDate, daysUntilExpiry, isRevoked, revocationReasonLabel } from '@/types';
import { StatusBadge, ExpiryBadge } from './StatusBadge';

interface CertificateTableProps {
  certificates: CertificateSummary[];
  sortBy?: string;
  sortDesc?: boolean;
  onSort: (column: string) => void;
  isLoading?: boolean;
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
  { key: 'notAfter', label: 'Expires', sortable: true },
  { key: 'requestor', label: 'ACME Contact', sortable: false },
];

function SortIcon({ column, sortBy, sortDesc }: { column: string; sortBy?: string; sortDesc?: boolean }) {
  if (sortBy !== column) return <ArrowUpDown className="h-3.5 w-3.5 text-slate-400" />;
  return sortDesc
    ? <ArrowDown className="h-3.5 w-3.5 text-certus-600" />
    : <ArrowUp className="h-3.5 w-3.5 text-certus-600" />;
}

function ExpiryCell({ cert }: { cert: CertificateSummary }) {
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
        {reason && <div className="text-xs text-slate-500">{reason}</div>}
      </div>
    );
  }

  const { notAfter } = cert;
  const days = daysUntilExpiry(notAfter);
  const dateStr = formatDate(notAfter);

  let daysLabel: string;
  let daysClass: string;
  if (days < 0) {
    daysLabel = `${Math.abs(days)}d ago`;
    daysClass = 'text-red-600';
  } else if (days <= 30) {
    daysLabel = `${days}d left`;
    daysClass = 'text-amber-600';
  } else {
    daysLabel = `${days}d left`;
    daysClass = 'text-slate-500';
  }

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
}: CertificateTableProps) {
  return (
    <div className="overflow-x-auto rounded-lg border border-slate-200 bg-white">
      <table className="min-w-full divide-y divide-slate-200">
        <thead className="bg-slate-50">
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
                className="px-4 py-3 text-left text-xs font-semibold text-slate-600 uppercase tracking-wider"
              >
                {col.sortable ? (
                  <button
                    type="button"
                    onClick={() => onSort(col.key)}
                    className="flex items-center gap-1.5 select-none rounded hover:text-slate-900 focus:outline-none focus-visible:ring-2 focus-visible:ring-certus-500"
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
        <tbody className="divide-y divide-slate-100">
          {isLoading && certificates.length === 0 ? (
            <tr>
              <td colSpan={columns.length} className="px-4 py-12 text-center text-slate-400">
                Loading certificates...
              </td>
            </tr>
          ) : certificates.length === 0 ? (
            <tr>
              <td colSpan={columns.length} className="px-4 py-12 text-center text-slate-400">
                No certificates found
              </td>
            </tr>
          ) : (
            certificates.map((cert) => (
              <tr
                key={cert.id}
                className="hover:bg-slate-50 transition-colors"
              >
                <td className="px-4 py-3">
                  <Link
                    to={`/certificates/${cert.id}`}
                    className="text-sm font-medium text-certus-700 hover:text-certus-900 hover:underline"
                  >
                    {certificateDisplayName(cert)}
                  </Link>
                  {cert.subjectAlternativeNames && (
                    <div className="text-xs text-slate-400 mt-0.5 truncate max-w-xs">
                      SANs: {cert.subjectAlternativeNames}
                    </div>
                  )}
                </td>
                <td className="px-4 py-3">
                  <span className="inline-flex items-center px-2 py-0.5 rounded bg-slate-100 text-xs font-medium text-slate-700">
                    {cert.templateName}
                  </span>
                </td>
                <td className="px-4 py-3 text-sm text-slate-500 font-mono text-xs">
                  {cert.serialNumber}
                </td>
                <td className="px-4 py-3">
                  <div className="flex items-center gap-1.5">
                    <StatusBadge status={cert.status} />
                    {!isRevoked(cert) && <ExpiryBadge notAfter={cert.notAfter} />}
                  </div>
                </td>
                <td className="px-4 py-3">
                  <ExpiryCell cert={cert} />
                </td>
                <td className="px-4 py-3 text-sm text-slate-500">
                  {cert.acmeContactEmail ?? '—'}
                </td>
              </tr>
            ))
          )}
        </tbody>
      </table>
    </div>
  );
}
