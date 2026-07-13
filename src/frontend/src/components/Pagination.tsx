import { ChevronLeft, ChevronRight } from 'lucide-react';

interface PaginationProps {
  skip: number;
  take: number;
  totalCount: number;
  onPageChange: (skip: number) => void;
}

export function Pagination({ skip, take, totalCount, onPageChange }: PaginationProps) {
  const currentPage = Math.floor(skip / take) + 1;
  const totalPages = Math.max(1, Math.ceil(totalCount / take));
  const canPrev = skip > 0;
  const canNext = skip + take < totalCount;

  return (
    <div className="flex items-center justify-between px-1 py-3">
      <div className="text-sm text-slate-500">
        Showing {totalCount === 0 ? 0 : skip + 1}
        {' '}&ndash;{' '}
        {Math.min(skip + take, totalCount)} of {totalCount.toLocaleString()} certificates
      </div>

      <div className="flex items-center gap-2">
        <button
          onClick={() => onPageChange(Math.max(0, skip - take))}
          disabled={!canPrev}
          className="inline-flex items-center px-3 py-1.5 border border-slate-300 rounded-md text-sm
                     font-medium text-slate-700 bg-white hover:bg-slate-50 disabled:opacity-50
                     disabled:cursor-not-allowed transition-colors"
        >
          <ChevronLeft className="h-4 w-4 mr-1" />
          Previous
        </button>

        <span className="text-sm text-slate-600 tabular-nums">
          Page {currentPage} of {totalPages}
        </span>

        <button
          onClick={() => onPageChange(skip + take)}
          disabled={!canNext}
          className="inline-flex items-center px-3 py-1.5 border border-slate-300 rounded-md text-sm
                     font-medium text-slate-700 bg-white hover:bg-slate-50 disabled:opacity-50
                     disabled:cursor-not-allowed transition-colors"
        >
          Next
          <ChevronRight className="h-4 w-4 ml-1" />
        </button>
      </div>
    </div>
  );
}
