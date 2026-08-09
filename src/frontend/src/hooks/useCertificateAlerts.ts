import { useQuery } from '@tanstack/react-query';
import { fetchCertificateAlertHistory } from '@/api/alerts';

/** Query key for one certificate's alert ladder. */
export const certificateAlertsKey = (id: number) =>
  ['alerts', 'certificate', id] as const;

/**
 * The alert ladder for one certificate (issue #160): which thresholds fired,
 * which failed, and which should have fired and did not.
 *
 * Not cached for long. Unlike the alert configuration, this changes on its own
 * as the monitor runs, and a stale answer here is exactly the "nobody was told"
 * blind spot the block exists to remove.
 */
export function useCertificateAlerts(id: number) {
  return useQuery({
    queryKey: certificateAlertsKey(id),
    queryFn: () => fetchCertificateAlertHistory(id),
    enabled: id > 0,
    staleTime: 30_000,
  });
}
