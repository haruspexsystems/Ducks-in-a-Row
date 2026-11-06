import { useQuery } from '@tanstack/react-query';
import { fetchSystemInfo } from '@/api/settings';

/** Query key for /api/settings/info, shared by the Settings page and the mode checks. */
export const systemInfoKey = ['settings', 'info'] as const;

/**
 * The running version, commit and instance mode. All three change only across
 * a service restart, so there is no point refetching on every tab focus.
 */
export function useSystemInfo() {
  return useQuery({
    queryKey: systemInfoKey,
    queryFn: fetchSystemInfo,
    staleTime: 5 * 60_000,
    retry: false,
    refetchOnWindowFocus: false,
  });
}

/**
 * True only once the server has said it runs in monitor mode (issue #470).
 * While the answer is loading, or if it could not be read, this is false, so
 * the dashboard keeps showing full mode exactly as it always has; the server
 * refuses every write in monitor mode whatever the page shows.
 */
export function useMonitorMode(): boolean {
  const { data } = useSystemInfo();
  return data?.mode === 'monitor';
}
