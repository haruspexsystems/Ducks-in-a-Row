import { X } from 'lucide-react';
import { ApiError } from '@/api/client';

/**
 * Dismissible notice for a failed manual sync (issue #157). Renders the
 * problem title and detail parsed from the API error, so the reader can tell
 * a CA that is unreachable (try again shortly) from one that denied view
 * access (grant Read on the CA; the detail carries the exact remediation).
 * Distinct from ApiErrorNotice, which replaces a page that failed to load;
 * here the page is fine and only the sync attempt failed.
 */
export function SyncErrorNotice({
  error,
  onDismiss,
}: {
  error: unknown;
  onDismiss: () => void;
}) {
  const apiError = error instanceof ApiError ? error : undefined;
  const title = apiError?.problemTitle ?? 'Could not sync from the CA';
  const detail =
    apiError?.problemDetail ?? (error instanceof Error ? error.message : String(error));

  return (
    <div
      role="alert"
      className="flex items-start justify-between gap-3 bg-amber-50 dark:bg-amber-500/10 border border-amber-200 dark:border-amber-500/30 rounded-lg px-4 py-3 text-amber-800 dark:text-amber-300"
    >
      <div>
        <p className="text-sm font-semibold">{title}</p>
        <p className="text-sm mt-0.5">{detail}</p>
      </div>
      <button
        type="button"
        onClick={onDismiss}
        aria-label="Dismiss"
        className="mt-0.5 text-amber-700 dark:text-amber-300 hover:text-amber-900 dark:text-amber-200 transition-colors"
      >
        <X className="h-4 w-4" />
      </button>
    </div>
  );
}
