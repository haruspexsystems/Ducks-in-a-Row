import type { ReactNode } from 'react';
import { Navigate } from 'react-router';
import { useSystemInfo } from '@/hooks/useSystemInfo';

/**
 * A page that exists only in full mode (issue #470). In monitor mode a
 * bookmark or a typed address lands on the dashboard instead, the way an
 * unknown path does, because the server answers none of the page's API calls
 * there.
 *
 * It waits for the mode before rendering the page. Rendering first and
 * redirecting once the answer arrived mounted the page for a moment, long
 * enough to fire its requests and log a 404 for each. If the mode cannot be
 * read at all, the page renders as it always has; the server refuses
 * whatever monitor mode forbids regardless.
 */
export function FullModeOnly({ children }: { children: ReactNode }) {
  const { data, isPending } = useSystemInfo();

  // Pending only until the first answer or the first failure; a failure
  // falls through to the page below.
  if (isPending) {
    return null;
  }

  if (data?.mode === 'monitor') {
    return <Navigate to="/" replace />;
  }

  return <>{children}</>;
}
