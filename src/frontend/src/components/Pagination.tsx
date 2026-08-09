import { ChevronLeft, ChevronRight } from 'lucide-react';

interface PaginationProps {
  skip: number;
  take: number;
  totalCount: number;
  onPageChange: (skip: number) => void;
  /** Noun after the count, e.g. "accounts". Defaults to "certificates". */
  itemsLabel?: string;
  /**
   * When both of these are set, a page size select renders beside the count.
   * A caller that passes neither gets the count and the buttons alone.
   */
  pageSizeOptions?: number[];
  onPageSizeChange?: (take: number) => void;
  /**
   * The select's controlled value. The take prop is the server echo of the
   * rendered rows, which under keepPreviousData is the previous response
   * while a fetch is in flight; a select bound to it snaps back to the old
   * size until the new page lands. Pass the query derived size instead.
   * Falls back to take when absent.
   */
  pageSize?: number;
}

export function Pagination({
  skip,
  take,
  totalCount,
  onPageChange,
  itemsLabel = 'certificates',
  pageSizeOptions,
  onPageSizeChange,
  pageSize,
}: PaginationProps) {
  const currentPage = Math.floor(skip / take) + 1;
  const totalPages = Math.max(1, Math.ceil(totalCount / take));
  const canPrev = skip > 0;
  const canNext = skip + take < totalCount;

  return (
    <div className="flex items-center justify-between px-1 py-3">
      <div className="flex items-center gap-3">
        <div className="text-sm text-muted">
          Showing {totalCount === 0 ? 0 : skip + 1}
          {' '}&ndash;{' '}
          {Math.min(skip + take, totalCount)} of {totalCount.toLocaleString()} {itemsLabel}
        </div>
        {pageSizeOptions && onPageSizeChange && (
          <select
            value={pageSize ?? take}
            onChange={(e) => onPageSizeChange(Number(e.target.value))}
            aria-label="Rows per page"
            className="px-2 py-1.5 border border-hairline-strong rounded-md text-sm bg-surface
                       focus:outline-none focus:ring-2 focus:ring-certus-500"
          >
            {pageSizeOptions.map((size) => (
              <option key={size} value={size}>
                {size} per page
              </option>
            ))}
          </select>
        )}
      </div>

      <div className="flex items-center gap-2">
        <button
          onClick={() => onPageChange(Math.max(0, skip - take))}
          disabled={!canPrev}
          className="inline-flex items-center px-3 py-1.5 border border-hairline-strong rounded-md text-sm
                     font-medium text-ink-soft bg-surface hover:bg-sunken disabled:opacity-50
                     disabled:cursor-not-allowed transition-colors"
        >
          <ChevronLeft className="h-4 w-4 mr-1" />
          Previous
        </button>

        <span className="text-sm text-ink-mid tabular-nums">
          Page {currentPage} of {totalPages}
        </span>

        <button
          onClick={() => onPageChange(skip + take)}
          disabled={!canNext}
          className="inline-flex items-center px-3 py-1.5 border border-hairline-strong rounded-md text-sm
                     font-medium text-ink-soft bg-surface hover:bg-sunken disabled:opacity-50
                     disabled:cursor-not-allowed transition-colors"
        >
          Next
          <ChevronRight className="h-4 w-4 ml-1" />
        </button>
      </div>
    </div>
  );
}
