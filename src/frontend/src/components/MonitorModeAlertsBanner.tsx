import { useQuery } from '@tanstack/react-query';
import { Link } from 'react-router';
import { BellOff } from 'lucide-react';
import { fetchAlertConfig } from '@/api/alerts';
import { alertConfigKey } from '@/hooks/useExpiryWarningDays';
import { useMonitorMode } from '@/hooks/useSystemInfo';
import { alertsAttention } from '@/lib/alerts';

/**
 * Dashboard wide warning while a monitor mode server can alert nobody (issue
 * #471). In monitor mode alerts are the product: they are how an expiring
 * certificate or a stale revocation list reaches anyone. With alerting off, or
 * with neither email nor a webhook able to deliver, the expiry monitor skips its
 * pass with nothing but a Debug line to show for it, so the dashboard says so.
 *
 * Shares the alert card's query key, so the two never disagree and the endpoint
 * is read once.
 */
export function MonitorModeAlertsBanner() {
  const monitorMode = useMonitorMode();
  const { data } = useQuery({
    queryKey: alertConfigKey,
    queryFn: fetchAlertConfig,
    staleTime: 5 * 60 * 1000,
    retry: false,
    enabled: monitorMode,
  });

  const attention = monitorMode ? alertsAttention(data) : null;
  if (attention === null) {
    return null;
  }

  return (
    <div className="bg-amber-400 text-amber-950">
      <div className="max-w-screen-2xl mx-auto px-4 sm:px-6 lg:px-8 py-1.5 flex flex-wrap items-center gap-2 text-xs font-semibold">
        <BellOff className="h-3.5 w-3.5" />
        {attention === 'disabled'
          ? 'Alerts are switched off, so nobody hears about an expiring certificate or a stale revocation list.'
          : 'No alert channel is set up, so nobody hears about an expiring certificate or a stale revocation list.'}
        <Link
          to="/settings#alerts"
          className="font-medium underline underline-offset-2 hover:no-underline"
        >
          Set up alerts
        </Link>
      </div>
    </div>
  );
}
