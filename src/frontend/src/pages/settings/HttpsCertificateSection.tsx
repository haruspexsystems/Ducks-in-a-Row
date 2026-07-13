import { useState } from 'react';
import { useQuery, useQueryClient } from '@tanstack/react-query';
import {
  AlertTriangle,
  BadgeCheck,
  Loader2,
  RefreshCw,
  ShieldAlert,
  ShieldCheck,
} from 'lucide-react';
import {
  fetchHttpsCertificate,
  renewHttpsCertificate,
  waitForHttpsCertificateApplied,
} from '@/api/settings';

type Phase = 'view' | 'confirm' | 'renewing' | 'restarting' | 'done' | 'manual-restart' | 'move-origin';

/**
 * The webserver HTTPS certificate section inside the External URL card:
 * shows the certificate the settings overlay points at (expiry, names,
 * thumbprint, template) and offers a one click renewal. Renewal re enrolls
 * with the template recorded at setup, applies the new thumbprint, and
 * restarts the service — the same restart and poll flow the URL save uses.
 */
export function HttpsCertificateSection() {
  const queryClient = useQueryClient();

  const { data: cert, isLoading, isError } = useQuery({
    queryKey: ['settings', 'https-certificate'],
    queryFn: fetchHttpsCertificate,
    staleTime: 30_000,
    retry: false,
  });

  const [phase, setPhase] = useState<Phase>('view');
  const [message, setMessage] = useState<string | null>(null);

  const handleRenew = async () => {
    setPhase('renewing');
    setMessage(null);

    try {
      const result = await renewHttpsCertificate();

      if (result.outcome !== 'installed') {
        // sanMismatch / pending / denied / failed: the message carries the
        // exact fix; nothing was applied.
        setMessage(result.message ?? 'Certificate renewal failed.');
        setPhase('view');
        return;
      }

      if (result.currentHostCovered === false) {
        // The new certificate does not cover the host this page is on, so
        // after the restart this origin stops answering TLS for this
        // browser. Polling from here would only time out; say where to go.
        setPhase('move-origin');
        return;
      }

      if (!result.restartScheduled) {
        setPhase('manual-restart');
        return;
      }

      setPhase('restarting');
      const applied = await waitForHttpsCertificateApplied(result.thumbprint);
      await queryClient.invalidateQueries({ queryKey: ['settings', 'https-certificate'] });
      setPhase(applied ? 'done' : 'manual-restart');
    } catch (err) {
      setMessage(err instanceof Error ? err.message : 'Certificate renewal failed.');
      setPhase('view');
    }
  };

  const notAfter = cert?.notAfter ? new Date(cert.notAfter) : null;
  const daysRemaining = notAfter
    ? Math.floor((notAfter.getTime() - Date.now()) / 86_400_000)
    : null;
  const expiryTone =
    daysRemaining === null ? 'text-slate-900'
    : daysRemaining < 0 ? 'text-red-700 font-semibold'
    : daysRemaining <= 30 ? 'text-amber-700 font-semibold'
    : 'text-slate-900';

  return (
    <div className="border-t border-slate-200 pt-4 space-y-3">
      <div className="flex items-center gap-2">
        <ShieldCheck className="h-4 w-4 text-certus-600" />
        <h3 className="text-sm font-semibold text-slate-900">HTTPS certificate</h3>
      </div>

      {isLoading && (
        <div className="flex items-center gap-2 text-sm text-slate-400 py-1">
          <Loader2 className="h-4 w-4 animate-spin" />
          Loading certificate details…
        </div>
      )}

      {isError && (
        <p className="text-xs text-slate-500">
          The certificate details could not be loaded. Check the service log.
        </p>
      )}

      {!isLoading && !isError && cert && !cert.configured && (
        <p className="text-xs text-slate-500">
          No CA issued HTTPS certificate is configured; the service serves its self
          signed fallback. The setup wizard can enroll one.
        </p>
      )}

      {!isLoading && !isError && cert?.configured && (
        <>
          <dl className="text-sm space-y-1">
            <div className="flex gap-2">
              <dt className="text-slate-500 min-w-[130px]">Expires:</dt>
              <dd className={`text-xs pt-0.5 ${expiryTone}`}>
                {notAfter ? notAfter.toLocaleDateString() : 'unknown'}
                {daysRemaining !== null && (
                  <span className="ml-1">
                    {daysRemaining < 0
                      ? '(expired)'
                      : `(${daysRemaining} ${daysRemaining === 1 ? 'day' : 'days'} left)`}
                  </span>
                )}
              </dd>
            </div>
            {cert.subjectNames && cert.subjectNames.length > 0 && (
              <div className="flex gap-2">
                <dt className="text-slate-500 min-w-[130px]">Names:</dt>
                <dd className="text-slate-900 font-mono text-xs pt-0.5">
                  {cert.subjectNames.join(', ')}
                </dd>
              </div>
            )}
            <div className="flex gap-2">
              <dt className="text-slate-500 min-w-[130px]">Thumbprint:</dt>
              <dd className="text-slate-900 font-mono text-xs pt-0.5 break-all">
                {cert.thumbprint}
              </dd>
            </div>
            <div className="flex gap-2">
              <dt className="text-slate-500 min-w-[130px]">Template:</dt>
              <dd className="text-slate-900 text-xs pt-0.5">
                {cert.template ??
                  (cert.renewTemplate
                    ? `${cert.renewTemplate} (first enabled template; none was recorded at setup)`
                    : 'unknown')}
              </dd>
            </div>
          </dl>

          {cert.inStore === false && (
            <div className="bg-amber-50 border border-amber-200 rounded-lg p-3 flex items-start gap-2">
              <ShieldAlert className="h-4 w-4 text-amber-600 mt-0.5" />
              <p className="text-xs text-amber-800">
                The configured certificate is no longer in the machine store; the
                service falls back to its self signed certificate. Renewing enrolls
                a fresh one.
              </p>
            </div>
          )}

          {cert.restartPending && phase === 'view' && (
            <p className="text-xs text-amber-700">
              A restart is pending before the configured certificate is served.
            </p>
          )}

          {phase === 'view' && (
            <button
              onClick={() => setPhase('confirm')}
              disabled={!cert.renewTemplate}
              className="inline-flex items-center gap-2 px-3 py-1.5 text-xs font-semibold
                         text-certus-700 bg-certus-50 border border-certus-200 rounded-lg
                         hover:bg-certus-100 disabled:opacity-50 transition-colors"
            >
              <RefreshCw className="h-3.5 w-3.5" />
              Renew certificate
            </button>
          )}

          {phase === 'confirm' && (
            <div className="bg-amber-50 border border-amber-200 rounded-lg p-3 space-y-2">
              <p className="text-xs font-semibold text-amber-900">
                Renew the webserver certificate now?
              </p>
              <p className="text-xs text-amber-800">
                A new certificate is requested from the CA with the{' '}
                <code className="font-mono">{cert.renewTemplate}</code> template. The
                service then restarts briefly to serve it; this page and ACME clients
                lose their connection for a few seconds.
              </p>
              <div className="flex gap-2">
                <button
                  onClick={handleRenew}
                  className="inline-flex items-center gap-2 px-3 py-1.5 text-xs font-semibold
                             text-amber-900 bg-amber-100 border border-amber-300 rounded-lg
                             hover:bg-amber-200 transition-colors"
                >
                  Renew and restart
                </button>
                <button
                  onClick={() => setPhase('view')}
                  className="inline-flex items-center gap-2 px-3 py-1.5 text-xs font-semibold
                             text-slate-700 bg-white border border-slate-300 rounded-lg
                             hover:bg-slate-50 transition-colors"
                >
                  Cancel
                </button>
              </div>
            </div>
          )}

          {(phase === 'renewing' || phase === 'restarting') && (
            <div className="bg-slate-50 border border-slate-200 rounded-lg p-3 flex items-start gap-2">
              <Loader2 className="h-4 w-4 text-certus-500 mt-0.5 animate-spin" />
              <div>
                <p className="text-xs font-semibold text-slate-900">
                  {phase === 'renewing'
                    ? 'Requesting a certificate from the CA'
                    : 'Certificate installed, the service is restarting'}
                </p>
                <p className="text-xs text-slate-500 mt-0.5">
                  {phase === 'restarting'
                    ? 'This page reconnects automatically; it usually takes a few seconds.'
                    : 'This should only take a moment.'}
                </p>
              </div>
            </div>
          )}

          {phase === 'done' && (
            <div className="bg-emerald-50 border border-emerald-200 rounded-lg p-3 flex items-start gap-2">
              <BadgeCheck className="h-4 w-4 text-emerald-600 mt-0.5" />
              <p className="text-xs text-emerald-800">
                The service restarted and now serves the renewed certificate.
              </p>
            </div>
          )}

          {phase === 'manual-restart' && (
            <div className="bg-amber-50 border border-amber-200 rounded-lg p-3 flex items-start gap-2">
              <AlertTriangle className="h-4 w-4 text-amber-600 mt-0.5" />
              <div>
                <p className="text-xs font-semibold text-amber-900">
                  Certificate renewed, restart needed
                </p>
                <p className="text-xs text-amber-700 mt-0.5">
                  The new certificate is installed and configured, but the service
                  did not confirm the restart. Restart it manually (
                  <code className="font-mono">Restart-Service DucksInARow</code>
                  ), then reload this page.
                </p>
              </div>
            </div>
          )}

          {phase === 'move-origin' && (
            <div className="bg-certus-50 border border-certus-200 rounded-lg p-3 flex items-start gap-2">
              <ShieldAlert className="h-4 w-4 text-certus-600 mt-0.5" />
              <p className="text-xs text-certus-800">
                The renewed certificate does not cover{' '}
                <code className="font-mono">{window.location.hostname}</code>, so this
                page loses its connection when the service restarts. Continue at the
                external URL afterwards.
              </p>
            </div>
          )}

          {message && phase === 'view' && (
            <div className="bg-red-50 border border-red-200 rounded-lg p-3 flex items-start gap-2">
              <AlertTriangle className="h-4 w-4 text-red-500 mt-0.5" />
              <p className="text-xs text-red-700 whitespace-pre-line">{message}</p>
            </div>
          )}
        </>
      )}
    </div>
  );
}
