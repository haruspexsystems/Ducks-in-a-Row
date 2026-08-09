import type { ReactNode } from 'react';
import { ArrowDown, ArrowUp, ArrowUpDown, Loader2 } from 'lucide-react';
import type { AcmeAccountRow } from '@/api/acme';
import { CopyButton } from '@/components/CopyButton';
import { formatDate, formatDateTime } from '@/types';

interface ColumnDef {
  key: string;
  label: string;
  sortable: boolean;
  align?: 'right';
}

/**
 * Orders and Last order are deliberately unsortable. Both are correlated
 * subqueries over the order table, so sorting on one would evaluate it for
 * every account in the filtered set rather than the page; the activity filter
 * answers those questions instead. Contact is unsortable for a different
 * reason: the column stores a raw JSON array, so ordering it would order the
 * JSON text including the mailto prefix.
 */
const columns: ColumnDef[] = [
  { key: 'accountId', label: 'Account', sortable: true },
  { key: 'status', label: 'Status', sortable: true },
  { key: 'contact', label: 'Contact', sortable: false },
  { key: 'credential', label: 'Credential', sortable: true },
  { key: 'orders', label: 'Orders', sortable: false },
  { key: 'lastOrder', label: 'Last order', sortable: false },
  { key: 'createdAt', label: 'Registered', sortable: true },
  { key: 'actions', label: 'Actions', sortable: false, align: 'right' },
];

const accountStatusColors: Record<string, string> = {
  valid: 'bg-emerald-100 dark:bg-emerald-500/15 text-emerald-800 dark:text-emerald-300',
  deactivated: 'bg-sunken-strong text-ink-strong',
};

function SortIcon({ column, sortBy, sortDesc }: { column: string; sortBy?: string; sortDesc?: boolean }) {
  if (sortBy !== column) return <ArrowUpDown className="h-3.5 w-3.5 text-faint" />;
  return sortDesc
    ? <ArrowDown className="h-3.5 w-3.5 text-certus-600" />
    : <ArrowUp className="h-3.5 w-3.5 text-certus-600" />;
}

interface AcmeAccountsTableProps {
  accounts: AcmeAccountRow[];
  /**
   * Whether EAB enforcement is Required. Only then is an unbound account
   * grandfathered rather than simply unbound, so only then is the pill amber.
   */
  requiredMode: boolean;
  sortBy?: string;
  sortDesc?: boolean;
  onSort: (column: string) => void;
  isLoading?: boolean;
  emptyState?: ReactNode;
  /** The row showing its deactivation confirm, or null. */
  confirmId: number | null;
  onConfirmChange: (id: number | null) => void;
  /** The row whose deactivation is in flight, or null. */
  busyId: number | null;
  onDeactivate: (id: number) => void;
}

/**
 * The ACME account inventory table. Sorting is presentational only: the
 * header reports the order the server applied and asks for a new one, which
 * keeps the sort correct across pages rather than only within the visible
 * twenty five rows.
 */
export function AcmeAccountsTable({
  accounts,
  requiredMode,
  sortBy,
  sortDesc,
  onSort,
  isLoading,
  emptyState,
  confirmId,
  onConfirmChange,
  busyId,
  onDeactivate,
}: AcmeAccountsTableProps) {
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
                className={`px-4 py-3 text-xs font-semibold text-ink-mid uppercase tracking-wider ${
                  col.align === 'right' ? 'text-right' : 'text-left'
                }`}
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
                  <div className={`flex items-center gap-1.5 ${col.align === 'right' ? 'justify-end' : ''}`}>
                    {col.label}
                  </div>
                )}
              </th>
            ))}
          </tr>
        </thead>
        <tbody className="divide-y divide-hairline-soft">
          {isLoading && accounts.length === 0 ? (
            <tr>
              <td colSpan={columns.length} className="px-4 py-12 text-center text-faint">
                Loading accounts...
              </td>
            </tr>
          ) : accounts.length === 0 ? (
            <tr>
              <td colSpan={columns.length} className="px-4 py-12 text-center text-faint">
                {emptyState ?? 'No accounts found'}
              </td>
            </tr>
          ) : (
            accounts.map((account) => (
              <AccountRow
                key={account.id}
                account={account}
                requiredMode={requiredMode}
                confirming={confirmId === account.id}
                onConfirmChange={(on) => onConfirmChange(on ? account.id : null)}
                busy={busyId === account.id}
                onDeactivate={() => onDeactivate(account.id)}
              />
            ))
          )}
        </tbody>
      </table>
    </div>
  );
}

function AccountRow({
  account,
  requiredMode,
  confirming,
  onConfirmChange,
  busy,
  onDeactivate,
}: {
  account: AcmeAccountRow;
  requiredMode: boolean;
  confirming: boolean;
  onConfirmChange: (on: boolean) => void;
  busy: boolean;
  onDeactivate: () => void;
}) {
  const statusClass = accountStatusColors[account.status] ?? 'bg-sunken-strong text-ink-strong';

  return (
    <tr className="hover:bg-sunken transition-colors">
      <td className="px-4 py-3 align-top">
        <span className="inline-flex items-center gap-1.5 font-mono text-xs text-ink-soft">
          {account.accountId}
          <CopyButton value={account.accountId} label="account id" />
        </span>
      </td>
      <td className="px-4 py-3 align-top">
        <span
          className={`inline-flex items-center px-2 py-0.5 rounded-full text-xs font-medium ${statusClass}`}
        >
          {account.status}
        </span>
      </td>
      <td className="px-4 py-3 align-top text-xs text-ink-mid break-all">
        {account.contacts && account.contacts.length > 0
          ? account.contacts.map((c) => c.replace(/^mailto:/, '')).join(', ')
          : '—'}
      </td>
      <td className="px-4 py-3 align-top">
        {account.credential ? (
          <span className="text-xs text-ink-soft">
            {account.credential.name}
            {account.credential.status === 'revoked' && (
              <span className="ml-1.5 text-violet-700 dark:text-violet-300 font-medium">(revoked)</span>
            )}
          </span>
        ) : (
          <span
            className={`inline-flex items-center px-2 py-0.5 rounded-full text-xs font-medium ${
              requiredMode && account.status === 'valid'
                ? 'bg-amber-100 dark:bg-amber-500/15 text-amber-800 dark:text-amber-300'
                : 'bg-sunken-strong text-ink-mid'
            }`}
            title={
              requiredMode && account.status === 'valid'
                ? 'Registered before enforcement was required; grandfathered and still working.'
                : 'Registered without an EAB credential.'
            }
          >
            Unbound
          </span>
        )}
      </td>
      <td className="px-4 py-3 align-top text-sm text-ink-soft tabular-nums">{account.ordersCount}</td>
      <td className="px-4 py-3 align-top text-muted whitespace-nowrap text-xs">
        {account.lastOrderAt ? formatDateTime(account.lastOrderAt) : '—'}
      </td>
      <td className="px-4 py-3 align-top text-muted whitespace-nowrap text-xs">
        {formatDate(account.createdAt)}
      </td>
      <td className="px-4 py-3 align-top text-right whitespace-nowrap">
        {busy ? (
          <Loader2 className="h-4 w-4 animate-spin inline text-faint" />
        ) : confirming ? (
          <span className="inline-flex items-center gap-2 text-xs">
            <span className="text-ink-mid">Deactivate? This cannot be undone.</span>
            <button
              onClick={onDeactivate}
              className="font-semibold text-red-600 hover:text-red-800 dark:text-red-300"
            >
              Confirm
            </button>
            <button
              onClick={() => onConfirmChange(false)}
              className="text-muted hover:text-ink-soft"
            >
              Cancel
            </button>
          </span>
        ) : account.status === 'valid' ? (
          <button
            onClick={() => onConfirmChange(true)}
            className="text-xs font-medium text-red-600 hover:text-red-800 dark:text-red-300"
          >
            Deactivate
          </button>
        ) : null}
      </td>
    </tr>
  );
}
