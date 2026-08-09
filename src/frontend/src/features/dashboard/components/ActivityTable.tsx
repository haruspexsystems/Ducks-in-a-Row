import { useMemo, useState } from 'react';
import {
  createColumnHelper,
  flexRender,
  getCoreRowModel,
  getSortedRowModel,
  useReactTable,
  type SortingState,
} from '@tanstack/react-table';
import { Zap, ArrowUpDown } from 'lucide-react';
import { card, mono, textInk, textMuted, textFaint, cn } from '../lib/ui';
import { STATUS, alpha, ACCENT } from '../lib/colors';
import { useIsDark } from '../lib/useIsDark';
import { DataIcon } from './Icon';
import type { ActivityItem, ActivityType } from '../data/types';

const VERB: Record<ActivityType, string> = {
  issued: 'Issued',
  renewed: 'Renewed',
  expired: 'Expired',
  revoked: 'Revoked',
  warning: 'Warning',
  rejected: 'Rejected',
};

const columnHelper = createColumnHelper<ActivityItem>();

export function ActivityTable({ data }: { data: ActivityItem[] }) {
  const dark = useIsDark();
  const [sorting, setSorting] = useState<SortingState>([]);

  const columns = useMemo(
    () => [
      columnHelper.accessor('cn', {
        header: 'Resource',
        enableSorting: true,
        cell: (info) => {
          const a = info.row.original;
          const c = STATUS[a.status].solid;
          return (
            <div className="flex items-center gap-3.5">
              <span
                className="grid h-8 w-8 shrink-0 place-items-center rounded-[9px]"
                style={{ background: alpha(c, dark ? 0.18 : 0.12), color: c }}
              >
                <DataIcon name={a.icon} size={16} strokeWidth={2.1} />
              </span>
              <span className={cn(mono, 'truncate text-[13.5px] font-semibold', textInk)}>{a.cn}</span>
            </div>
          );
        },
      }),
      columnHelper.accessor('tmpl', {
        header: 'Event',
        enableSorting: false,
        cell: (info) => {
          const a = info.row.original;
          const c = STATUS[a.status].solid;
          return (
            <div className="truncate text-xs">
              <span className="font-bold" style={{ color: c }}>{VERB[a.type] ?? a.type}</span>
              <span className="mx-[5px] opacity-50">·</span>
              <span className={textMuted}>{a.tmpl}</span>
            </div>
          );
        },
      }),
      columnHelper.accessor('ts', {
        header: 'When',
        enableSorting: true,
        cell: (info) => <span className={cn(mono, 'whitespace-nowrap text-[11.5px]', textFaint)}>{info.row.original.time}</span>,
      }),
    ],
    [dark],
  );

  const table = useReactTable({
    data,
    columns,
    state: { sorting },
    onSortingChange: setSorting,
    getCoreRowModel: getCoreRowModel(),
    getSortedRowModel: getSortedRowModel(),
  });

  return (
    <div className={cn(card, 'flex flex-col overflow-hidden')}>
      {/* header */}
      <div className="flex items-center justify-between border-b border-slate-900/[0.08] px-[18px] pb-3 pt-4 dark:border-slate-400/[0.16]">
        <div className="flex min-w-0 items-center gap-2.5">
          <Zap size={17} color={ACCENT} />
          <span className={cn('whitespace-nowrap text-[15px] font-bold leading-tight', textInk)}>Recent Activity</span>
        </div>
      </div>

      <table className="w-full border-collapse">
        <thead>
          {table.getHeaderGroups().map((hg) => (
            <tr key={hg.id} className="border-b border-slate-900/[0.06] dark:border-slate-400/[0.1]">
              {hg.headers.map((header) => {
                const sortable = header.column.getCanSort();
                const dir = header.column.getIsSorted();
                return (
                  <th
                    key={header.id}
                    aria-sort={
                      sortable && dir ? (dir === 'desc' ? 'descending' : 'ascending') : undefined
                    }
                    className={cn(
                      'px-[18px] py-2 text-left text-[11px] font-semibold uppercase tracking-[0.4px]',
                      textFaint,
                      header.column.id === 'ts' && 'text-right',
                    )}
                  >
                    {sortable ? (
                      <button
                        type="button"
                        onClick={header.column.getToggleSortingHandler()}
                        className={cn(
                          'inline-flex items-center gap-1 transition-colors hover:text-slate-600 dark:hover:text-slate-300',
                          header.column.id === 'ts' && 'ml-auto',
                          dir && 'text-slate-600 dark:text-slate-300',
                        )}
                      >
                        {flexRender(header.column.columnDef.header, header.getContext())}
                        <ArrowUpDown size={11} className={dir ? 'opacity-100' : 'opacity-40'} />
                      </button>
                    ) : (
                      flexRender(header.column.columnDef.header, header.getContext())
                    )}
                  </th>
                );
              })}
            </tr>
          ))}
        </thead>
        <tbody>
          {table.getRowModel().rows.map((row) => (
            <tr
              key={row.id}
              className="border-t border-slate-900/[0.06] transition-colors first:border-t-0 hover:bg-slate-900/[0.025] dark:border-slate-400/[0.1] dark:hover:bg-slate-400/[0.06]"
            >
              {row.getVisibleCells().map((cell) => (
                <td
                  key={cell.id}
                  className={cn(
                    'px-[18px] py-[11px] align-middle',
                    cell.column.id === 'cn' && 'min-w-0 max-w-0 w-full',
                    cell.column.id === 'ts' && 'text-right',
                  )}
                >
                  {flexRender(cell.column.columnDef.cell, cell.getContext())}
                </td>
              ))}
            </tr>
          ))}
        </tbody>
      </table>
    </div>
  );
}
