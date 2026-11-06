import { useEffect, useRef, useState } from 'react';
import { useLocation } from 'react-router';
import { useQueryClient } from '@tanstack/react-query';
import { AlertTriangle, BadgeCheck, CheckCircle2, Info, Loader2, RefreshCw, RotateCcw, Trash2, Upload } from 'lucide-react';
import { errorText } from '@/api/client';
import {
  removeLicence,
  restorePreviousLicence,
  retryModule,
  waitForModuleRestart,
  type LicenceStatusResponse,
} from '@/api/licence';
import { licenceKey, useLicence } from '@/hooks/useLicence';
import { describeLicence, NOT_AFFECTED, type LicenceTone } from '@/lib/licence';
import { LicenceFacts } from './LicenceFacts';
import { LicenceUpload } from './LicenceUpload';

type Panel = 'none' | 'upload' | 'confirmRemove' | 'confirmRetry';
type RetryPhase = 'idle' | 'restarting' | 'manual' | 'timedOut';

const toneClasses: Record<LicenceTone, string> = {
  neutral: 'bg-sunken border-hairline text-ink-soft',
  good: 'bg-emerald-50 dark:bg-emerald-500/10 border-emerald-200 dark:border-emerald-500/30 text-emerald-800 dark:text-emerald-300',
  amber: 'bg-amber-50 dark:bg-amber-500/10 border-amber-200 dark:border-amber-500/30 text-amber-800 dark:text-amber-300',
  red: 'bg-red-50 dark:bg-red-500/10 border-red-200 dark:border-red-500/30 text-red-700 dark:text-red-300',
  grey: 'bg-sunken-strong border-hairline text-ink-soft',
};

/**
 * The licence card on the Settings page (licence design sections 13.3 and 13.4,
 * issue #493). It drives every route of /api/settings/licence: preview and
 * install a licence file, remove it, restore the previous one, and retry a paid
 * module that was set aside. The paid tier is all it governs; certificate
 * issuance and renewal never depend on it, and every warning says so.
 *
 * Every change answers with the new status, which is written straight into the
 * shared query, so the banner and the About block change with it. It is never
 * read again at once: for a moment after a change the server can still answer
 * with the verdict on the licence that was replaced.
 */
export function LicenceCard() {
  const queryClient = useQueryClient();
  const { data, isLoading, error } = useLicence();
  const [panel, setPanelState] = useState<Panel>('none');
  const [busy, setBusy] = useState(false);
  const [actionError, setActionError] = useState<string | null>(null);
  const [done, setDone] = useState<string | null>(null);
  const [retryPhase, setRetryPhase] = useState<RetryPhase>('idle');

  // The licence banner links here. Scroll once the card has its content, and
  // once per navigation, the way the alerts card does.
  const location = useLocation();
  const cardRef = useRef<HTMLDivElement>(null);
  const scrolledFor = useRef<string | null>(null);
  useEffect(() => {
    if (location.hash !== '#licence' || scrolledFor.current === location.key || isLoading) return;
    scrolledFor.current = location.key;
    cardRef.current?.scrollIntoView({ behavior: 'smooth', block: 'start' });
  }, [location.hash, location.key, isLoading]);

  // Opening a panel clears the last outcome, so a confirmation never sits beside
  // the message of the change before it.
  const setPanel = (next: Panel) => {
    if (next !== 'none') {
      setDone(null);
      setActionError(null);
    }
    setPanelState(next);
  };

  const settle = (status: LicenceStatusResponse, message: string) => {
    queryClient.setQueryData(licenceKey, status);
    setPanel('none');
    setDone(message);
  };

  const run = async (action: () => Promise<void>) => {
    setBusy(true);
    setActionError(null);
    setDone(null);
    try {
      await action();
    } catch (err) {
      setActionError(errorText(err, 'The change could not be made.'));
    } finally {
      setBusy(false);
    }
  };

  const remove = () => run(async () => settle(await removeLicence(), 'The licence was removed. Restore previous licence puts it back.'));

  const restore = () => run(async () => settle(await restorePreviousLicence(), 'The previous licence was restored.'));

  const retry = () =>
    run(async () => {
      const result = await retryModule();
      setPanel('none');
      if (!result.restartScheduled) {
        setRetryPhase('manual');
        return;
      }
      setRetryPhase('restarting');
      const status = await waitForModuleRestart();
      if (status) queryClient.setQueryData(licenceKey, status);
      else await queryClient.invalidateQueries({ queryKey: licenceKey });
      setRetryPhase(status ? 'idle' : 'timedOut');
    });

  const description = data ? describeLicence(data) : null;
  const writable = data ? !data.stored.untrusted : false;

  return (
    <div id="licence" ref={cardRef} className="bg-surface border border-hairline rounded-lg p-6 space-y-4 scroll-mt-4">
      <div className="flex items-center gap-2">
        <BadgeCheck className="h-4 w-4 text-certus-600" />
        <h3 className="text-sm font-semibold text-ink">Licence</h3>
      </div>
      <p className="text-sm text-muted">
        A licence file switches on the paid tier, and the paid module checks it. Certificate issuance
        and renewal never depend on either.
      </p>

      {isLoading && (
        <div className="flex items-center gap-2 text-sm text-faint py-2">
          <Loader2 className="h-4 w-4 animate-spin" />
          Reading the licence status
        </div>
      )}

      {error != null && !data && (
        <div className="bg-red-50 dark:bg-red-500/10 border border-red-200 dark:border-red-500/30 rounded-lg p-3 flex items-start gap-2">
          <AlertTriangle className="h-4 w-4 text-red-500 mt-0.5 shrink-0" />
          <p className="text-xs text-red-700 dark:text-red-300">
            The licence status could not be read. {NOT_AFFECTED}
          </p>
        </div>
      )}

      {data && description && (
        <>
          <div className={`border rounded-lg p-3 space-y-1.5 ${toneClasses[description.tone]}`} data-testid="licence-status">
            {description.lines.map((line) => (
              <p key={line} className="text-sm">{line}</p>
            ))}
            {description.notes.map((note) => (
              <p key={note} className="text-xs">{note}</p>
            ))}
            {description.detail && (
              <p className="text-xs opacity-80">The service says: {description.detail}.</p>
            )}
          </div>

          {data.module.state === 'Loaded' && data.licence.isVerified && <LicenceFacts licence={data.licence} />}

          {data.module.id && (
            <p className="text-xs text-faint">
              Paid module {data.module.version ?? data.module.id}
            </p>
          )}

          {retryPhase === 'restarting' && (
            <div className="flex items-center gap-2 text-xs text-faint">
              <Loader2 className="h-4 w-4 animate-spin" />
              The service is restarting to try the paid module again
            </div>
          )}
          {/* Only while the module is still set aside: once it is not, the advice is stale. */}
          {(retryPhase === 'manual' || retryPhase === 'timedOut') && description.canRetry && (
            <div className="bg-sunken border border-hairline rounded-lg p-3 flex items-start gap-2">
              <Info className="h-4 w-4 text-faint mt-0.5 shrink-0" />
              <p className="text-xs text-ink-soft">
                {retryPhase === 'manual'
                  ? 'The service could not restart itself.'
                  : 'The service did not come back within 90 seconds.'}{' '}
                Restart it by hand (<code className="font-mono">Restart-Service DucksInARow</code>) to try
                the paid module again, then reload this page.
              </p>
            </div>
          )}

          {panel === 'none' && (
            <div className="flex flex-wrap gap-2">
              {writable && (
                <ActionButton onClick={() => setPanel('upload')} disabled={busy} icon={Upload}>
                  {data.stored.active ? 'Replace the licence' : 'Upload a licence'}
                </ActionButton>
              )}
              {writable && data.stored.active && (
                <ActionButton onClick={() => setPanel('confirmRemove')} disabled={busy} icon={Trash2}>
                  Remove the licence
                </ActionButton>
              )}
              {writable && data.stored.previous && (
                <ActionButton onClick={() => void restore()} disabled={busy} icon={RotateCcw}>
                  Restore previous licence
                </ActionButton>
              )}
              {description.canRetry && retryPhase !== 'restarting' && (
                <ActionButton onClick={() => setPanel('confirmRetry')} disabled={busy} icon={RefreshCw}>
                  Retry the paid module
                </ActionButton>
              )}
            </div>
          )}

          {panel === 'upload' && (
            <LicenceUpload
              installed={data}
              onInstalled={(status) =>
                settle(status, status.licence.status === 'StoredNotVerified'
                  ? 'The licence was stored. It is checked once the paid module runs.'
                  : 'The licence was installed.')}
              onCancel={() => setPanel('none')}
            />
          )}

          {panel === 'confirmRemove' && (
            <ConfirmPanel
              heading="Remove the licence?"
              confirmLabel="Remove"
              busy={busy}
              onConfirm={() => void remove()}
              onCancel={() => setPanel('none')}
            >
              Paid features will switch off. {NOT_AFFECTED} The licence is kept as the previous one,
              so Restore previous licence can put it back.
            </ConfirmPanel>
          )}

          {panel === 'confirmRetry' && (
            <ConfirmPanel
              heading="Retry the paid module?"
              confirmLabel="Restart and retry"
              busy={busy}
              onConfirm={() => void retry()}
              onCancel={() => setPanel('none')}
            >
              The service restarts to try the paid module again; this page and ACME clients lose their
              connection for a few seconds.
            </ConfirmPanel>
          )}

          {done && (
            <div className="bg-emerald-50 dark:bg-emerald-500/10 border border-emerald-200 dark:border-emerald-500/30 rounded-lg p-3 flex items-start gap-2">
              <CheckCircle2 className="h-4 w-4 text-emerald-600 mt-0.5 shrink-0" />
              <p className="text-xs text-emerald-800 dark:text-emerald-300">{done}</p>
            </div>
          )}

          {actionError && (
            <div className="bg-red-50 dark:bg-red-500/10 border border-red-200 dark:border-red-500/30 rounded-lg p-3 flex items-start gap-2">
              <AlertTriangle className="h-4 w-4 text-red-500 mt-0.5 shrink-0" />
              <p className="text-xs text-red-700 dark:text-red-300">{actionError}</p>
            </div>
          )}
        </>
      )}
    </div>
  );
}

function ActionButton({
  onClick,
  disabled,
  icon: Icon,
  children,
}: {
  onClick: () => void;
  disabled: boolean;
  icon: typeof Upload;
  children: React.ReactNode;
}) {
  return (
    <button
      type="button"
      onClick={onClick}
      disabled={disabled}
      className="inline-flex items-center gap-1.5 px-2.5 py-1 text-xs font-medium text-ink-soft
                 border border-hairline-strong rounded-lg hover:bg-sunken disabled:opacity-50 transition-colors"
    >
      <Icon className="h-3.5 w-3.5" />
      {children}
    </button>
  );
}

function ConfirmPanel({
  heading,
  confirmLabel,
  busy,
  onConfirm,
  onCancel,
  children,
}: {
  heading: string;
  confirmLabel: string;
  busy: boolean;
  onConfirm: () => void;
  onCancel: () => void;
  children: React.ReactNode;
}) {
  return (
    <div className="bg-amber-50 dark:bg-amber-500/10 border border-amber-200 dark:border-amber-500/30 rounded-lg p-3 space-y-2">
      <p className="text-xs font-semibold text-amber-900 dark:text-amber-200">{heading}</p>
      <p className="text-xs text-amber-800 dark:text-amber-300">{children}</p>
      <div className="flex gap-2">
        <button
          type="button"
          onClick={onConfirm}
          disabled={busy}
          className="inline-flex items-center gap-1.5 px-3 py-1.5 text-xs font-semibold text-white bg-amber-600 rounded-lg hover:bg-amber-700 disabled:opacity-60"
        >
          {busy && <Loader2 className="h-3.5 w-3.5 animate-spin" />}
          {confirmLabel}
        </button>
        <button
          type="button"
          onClick={onCancel}
          disabled={busy}
          className="px-3 py-1.5 text-xs font-medium text-muted hover:text-ink"
        >
          Cancel
        </button>
      </div>
    </div>
  );
}
