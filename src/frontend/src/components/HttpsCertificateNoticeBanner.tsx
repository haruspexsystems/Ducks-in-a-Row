import { useState } from 'react';
import { useQuery, useQueryClient } from '@tanstack/react-query';
import { AlertTriangle, Loader2, RefreshCw, ShieldAlert } from 'lucide-react';
import {
  applyHttpsCertificate,
  fetchHttpsCertificate,
  waitForHttpsCertificateApplied,
  type HttpsCertificateInfo,
} from '@/api/settings';

type Phase = 'idle' | 'applying' | 'restarting' | 'manual-restart';

/** Days until an ISO timestamp, or null when there is none. */
function daysUntil(iso?: string | null): number | null {
  if (!iso) return null;
  return Math.floor((new Date(iso).getTime() - Date.now()) / 86_400_000);
}

/**
 * Tone for the pending restart notice. It escalates on the certificate the
 * server is still *serving*, not the renewed one waiting in the overlay: the
 * renewal bought a full window of time, and the notice only becomes urgent as
 * that window runs out unapplied.
 */
function toneFor(daysRemaining: number | null) {
  if (daysRemaining === null || daysRemaining <= 3) {
    return { bar: 'bg-red-600 text-red-50', button: 'bg-red-800/40 hover:bg-red-800/60' };
  }
  if (daysRemaining <= 14) {
    return { bar: 'bg-amber-400 text-amber-950', button: 'bg-amber-600/20 hover:bg-amber-600/30' };
  }
  return { bar: 'bg-sky-100 dark:bg-sky-500/15 text-sky-900 dark:text-sky-200', button: 'bg-sky-600/15 hover:bg-sky-600/25' };
}

/**
 * Dashboard wide notice for the server's own HTTPS certificate (issue #105).
 *
 * Automatic renewal never restarts the service, so a renewed certificate sits
 * in the store and the settings overlay until someone applies it. That is a
 * state an administrator has to see from anywhere in the dashboard, not only
 * on the Settings page, because the running process keeps serving the old
 * certificate until then. The banner also carries a failed renewal, which is
 * the other thing they need to act on.
 *
 * Shares the Settings page's query key, so the two never disagree and the
 * endpoint is polled once, not twice.
 */
export function HttpsCertificateNoticeBanner() {
  const queryClient = useQueryClient();
  const [phase, setPhase] = useState<Phase>('idle');
  const [error, setError] = useState<string | null>(null);

  const { data } = useQuery<HttpsCertificateInfo>({
    queryKey: ['settings', 'https-certificate'],
    queryFn: fetchHttpsCertificate,
    staleTime: 30_000,
    retry: false,
    refetchOnWindowFocus: false,
  });

  const handleApply = async () => {
    setPhase('applying');
    setError(null);
    try {
      const result = await applyHttpsCertificate();
      if (!result.restartScheduled) {
        setPhase('manual-restart');
        return;
      }
      setPhase('restarting');
      const applied = await waitForHttpsCertificateApplied(result.thumbprint);
      await queryClient.invalidateQueries({ queryKey: ['settings', 'https-certificate'] });
      setPhase(applied ? 'idle' : 'manual-restart');
    } catch (err) {
      setError(err instanceof Error ? err.message : 'The certificate could not be applied.');
      setPhase('idle');
    }
  };

  if (!data?.configured) {
    return null;
  }

  if (data.restartPending) {
    const remaining = daysUntil(data.servedNotAfter);
    const tone = toneFor(remaining);
    const busy = phase === 'applying' || phase === 'restarting';

    return (
      <div className={tone.bar}>
        <div className="max-w-screen-2xl mx-auto px-4 sm:px-6 lg:px-8 py-1.5 flex flex-wrap items-center gap-x-2 gap-y-1 text-xs font-semibold">
          <ShieldAlert className="h-3.5 w-3.5 shrink-0" />
          <span>
            Server certificate renewed. Restart to apply it
            {remaining === null
              ? '; the certificate in use is no longer in the machine store.'
              : remaining <= 0
                ? '; the certificate in use has expired.'
                : ` — the one in use expires in ${remaining} ${remaining === 1 ? 'day' : 'days'}.`}
          </span>

          {phase === 'manual-restart' ? (
            <span className="font-normal">
              Restart the service by hand (<code className="font-mono">Restart-Service DucksInARow</code>),
              then reload this page.
            </span>
          ) : (
            <button
              onClick={handleApply}
              disabled={busy}
              className={`inline-flex items-center gap-1.5 rounded-md px-2 py-0.5 font-semibold
                          transition-colors disabled:opacity-60 ${tone.button}`}
            >
              {busy ? (
                <Loader2 className="h-3 w-3 animate-spin" />
              ) : (
                <RefreshCw className="h-3 w-3" />
              )}
              {phase === 'restarting' ? 'Restarting…' : phase === 'applying' ? 'Applying…' : 'Apply now'}
            </button>
          )}

          {error && <span className="font-normal">{error}</span>}
        </div>
      </div>
    );
  }

  if (data.autoRenewal?.failed) {
    return (
      <div className="bg-amber-400 text-amber-950">
        <div className="max-w-screen-2xl mx-auto px-4 sm:px-6 lg:px-8 py-1.5 flex flex-wrap items-center gap-x-2 gap-y-1 text-xs font-semibold">
          <AlertTriangle className="h-3.5 w-3.5 shrink-0" />
          <span>
            Automatic renewal of the server certificate failed. The current certificate is
            still in place; see Settings for the reason.
          </span>
        </div>
      </div>
    );
  }

  return null;
}
