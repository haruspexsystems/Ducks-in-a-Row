import { useQuery } from '@tanstack/react-query';
import { fetchAlertConfig } from '@/api/alerts';

/**
 * The window to assume before the real one has loaded, or if the alert config
 * cannot be read. Matches AlertOptions.DefaultExpiryWarningDays on the backend,
 * which is what an unconfigured install reports anyway, so a default install
 * behaves identically whether this request succeeded or not.
 */
export const DEFAULT_EXPIRY_WARNING_DAYS = 30;

/** Query key for the alert configuration, shared by every expiry surface. */
export const alertConfigKey = ['alerts', 'config'] as const;

/**
 * The operator's "expiring soon" window in days, for every expiry affordance in
 * the UI (issue #152).
 *
 * Before this, three surfaces each hardcoded 30 days and none of them read the
 * configured alert thresholds, so an operator alerting at 60 days got warning
 * emails about certificates the dashboard reported as fine.
 *
 * React Query dedupes on the key, so calling this once per table row costs one
 * request per page rather than one per row. That is why this is a hook rather
 * than a context provider or a prop threaded down from each page.
 */
export function useExpiryWarningDays(): number {
  const { data } = useQuery({
    queryKey: alertConfigKey,
    queryFn: fetchAlertConfig,
    // The window changes only when an operator edits configuration and restarts,
    // so this does not need to be fresh within a session.
    staleTime: 5 * 60 * 1000,
  });

  return data?.expiryWarningDays ?? DEFAULT_EXPIRY_WARNING_DAYS;
}
