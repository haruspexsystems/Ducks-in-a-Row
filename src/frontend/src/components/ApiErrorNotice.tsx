import { Lock, ShieldAlert } from 'lucide-react';
import { ApiError } from '@/api/client';

/**
 * Renders an API query error with specific guidance for authentication
 * failures: 401 means Windows Integrated Authentication did not complete;
 * 403 means the signed-in user is not in the Certus admin group. Anything
 * else falls back to the generic error panel.
 */
export function ApiErrorNotice({
  error,
  title = 'Failed to load data',
}: {
  error: unknown;
  title?: string;
}) {
  if (error instanceof ApiError && error.status === 401) {
    return (
      <div className="bg-amber-50 border border-amber-200 rounded-lg p-6 text-amber-800">
        <div className="flex items-center gap-2 mb-1">
          <Lock className="h-5 w-5" />
          <h2 className="text-lg font-semibold">Authentication required</h2>
        </div>
        <p className="text-sm">
          Certus uses Windows Integrated Authentication. Sign in with a Windows
          account, or check that this site is in your browser's intranet zone so
          credentials are sent automatically.
        </p>
      </div>
    );
  }

  if (error instanceof ApiError && error.status === 403) {
    return (
      <div className="bg-amber-50 border border-amber-200 rounded-lg p-6 text-amber-800">
        <div className="flex items-center gap-2 mb-1">
          <ShieldAlert className="h-5 w-5" />
          <h2 className="text-lg font-semibold">Not authorized</h2>
        </div>
        <p className="text-sm">
          You are signed in, but your account is not in the Certus admin group.
          Ask an administrator to add you to the configured group.
        </p>
      </div>
    );
  }

  return (
    <div className="bg-red-50 border border-red-200 rounded-lg p-6 text-red-700">
      <h2 className="text-lg font-semibold mb-1">{title}</h2>
      <p className="text-sm">
        {error instanceof Error ? error.message : String(error)}
      </p>
    </div>
  );
}
