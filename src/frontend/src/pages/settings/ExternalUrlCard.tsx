import { useState } from 'react';
import { useQuery, useQueryClient } from '@tanstack/react-query';
import {
  AlertTriangle,
  CheckCircle2,
  Globe,
  Loader2,
  RefreshCw,
  ShieldAlert,
} from 'lucide-react';
import {
  fetchExternalUrlSettings,
  updateExternalUrl,
  waitForExternalUrlApplied,
} from '@/api/settings';
import {
  validateExternalUrl,
  type SetupUnreachableUrlResponse,
  type UrlProbeResult,
} from '@/api/setup';
import { HttpsCertificateSection } from './HttpsCertificateSection';

type Phase = 'edit' | 'restarting' | 'applied' | 'manual-restart';

/**
 * Dashboard card for viewing and changing the external URL after setup
 * (issue #93). Shows the effective value and which configuration layer it
 * comes from; edits are validated like the setup wizard (static checks plus
 * the server side reachability probe) and applied by a service restart.
 */
export function ExternalUrlCard() {
  const queryClient = useQueryClient();

  const { data: settings, isLoading, isError } = useQuery({
    queryKey: ['settings', 'external-url'],
    queryFn: fetchExternalUrlSettings,
    staleTime: 30_000,
    retry: false,
  });

  const [url, setUrl] = useState<string | null>(null);
  const [phase, setPhase] = useState<Phase>('edit');
  const [validating, setValidating] = useState(false);
  const [saving, setSaving] = useState(false);
  const [validated, setValidated] = useState(false);
  const [error, setError] = useState<string | null>(null);
  const [warnings, setWarnings] = useState<string[]>([]);
  const [probe, setProbe] = useState<UrlProbeResult | null>(null);
  const [refusal, setRefusal] = useState<SetupUnreachableUrlResponse | null>(null);
  const [saveMessage, setSaveMessage] = useState<string | null>(null);

  // Until the admin types, the field shows what a save would start from: the
  // overlay value (a pending change included), falling back to the effective.
  const currentUrl = url ?? settings?.overlayUrl ?? settings?.effectiveUrl ?? '';
  const dirty = currentUrl !== (settings?.overlayUrl ?? settings?.effectiveUrl ?? '');
  const overriddenByOther = settings?.effectiveSource === 'other';

  const clearOutcome = () => {
    setError(null);
    setWarnings([]);
    setProbe(null);
    setRefusal(null);
    setValidated(false);
  };

  const handleUrlChange = (value: string) => {
    setUrl(value);
    clearOutcome();
  };

  const handleValidate = async () => {
    if (!currentUrl) return;
    setValidating(true);
    clearOutcome();

    try {
      // No template argument: the server probes the first enabled template's
      // ACME directory, the same target the save endpoint probes.
      const result = await validateExternalUrl(currentUrl);
      if (!result.valid) {
        setError(result.errorMessage ?? 'Invalid URL');
        return;
      }
      setWarnings(result.warnings ?? []);
      setProbe(result.probe ?? null);
      setValidated(true);
    } catch (err) {
      setError(err instanceof Error ? err.message : 'Validation failed');
    } finally {
      setValidating(false);
    }
  };

  const handleSave = async (confirmUnreachable: boolean) => {
    if (!currentUrl) return;
    setSaving(true);
    setError(null);
    setRefusal(null);

    try {
      const outcome = await updateExternalUrl(currentUrl, confirmUnreachable);

      if (outcome.kind === 'unreachableUrl') {
        // The save probe found the URL unreachable and it was not confirmed
        // yet. Show the outcome and let the admin decide, like the wizard.
        setRefusal(outcome.refusal);
        return;
      }

      setSaveMessage(outcome.result.message);
      if (outcome.result.restartScheduled) {
        setPhase('restarting');
        const applied = await waitForExternalUrlApplied(currentUrl);
        setPhase(applied ? 'applied' : 'manual-restart');
      } else {
        // Saved with no self restart: a development host, a console run, or
        // an environment override that a restart cannot beat. The server
        // message says which; the card shows it as is.
        setPhase('manual-restart');
      }
      // Deliberately not invalidating 'setup-config' here: its observer in
      // Layout drives the mock CA banner, and a refetch racing the restart
      // would blank the banner until something else refetches it.
      await queryClient.invalidateQueries({ queryKey: ['settings', 'external-url'] });
    } catch (err) {
      setError(err instanceof Error ? err.message : 'Saving failed');
    } finally {
      setSaving(false);
    }
  };

  const handleConfirmAnyway = () => {
    void handleSave(true);
  };

  const backToEdit = () => {
    setUrl(null);
    setPhase('edit');
    setSaveMessage(null);
    clearOutcome();
  };

  const probeFailed = probe !== null && probe.attempted && !probe.reachable;

  if (phase === 'restarting') {
    return (
      <Card>
        <div className="text-center py-8 space-y-4">
          <RefreshCw className="h-10 w-10 text-certus-500 mx-auto animate-spin" />
          <div>
            <h3 className="text-lg font-semibold text-slate-900">Applying the new URL</h3>
            <p className="text-sm text-slate-500 mt-1">
              The service is restarting to apply the change. This page reconnects
              automatically; it usually takes a few seconds.
            </p>
          </div>
        </div>
      </Card>
    );
  }

  if (phase === 'applied') {
    return (
      <Card>
        <div className="text-center py-8 space-y-4">
          <CheckCircle2 className="h-10 w-10 text-emerald-500 mx-auto" />
          <div>
            <h3 className="text-lg font-semibold text-slate-900">External URL applied</h3>
            <p className="text-sm text-slate-500 mt-1">
              ACME clients should target:{' '}
              <code className="font-mono">{currentUrl}/acme/{'{template}'}/directory</code>
            </p>
          </div>
          <button
            onClick={backToEdit}
            className="inline-flex items-center gap-2 px-4 py-2 text-sm font-medium text-white
                       bg-certus-600 rounded-lg hover:bg-certus-700 transition-colors"
          >
            Done
          </button>
        </div>
      </Card>
    );
  }

  if (phase === 'manual-restart') {
    return (
      <Card>
        <div className="text-center py-6 space-y-4">
          <AlertTriangle className="h-10 w-10 text-amber-500 mx-auto" />
          <div>
            <h3 className="text-lg font-semibold text-slate-900">URL saved, not applied yet</h3>
            <p className="text-sm text-slate-500 mt-1">
              {saveMessage ?? 'The change is saved but not applied yet. Restart the service, then reload.'}
            </p>
            {/* The restart command helps only when a restart can actually
                apply the change; with an environment override in force it
                cannot, and the server message above says so. */}
            {!overriddenByOther && (
              <code className="inline-block bg-slate-100 border border-slate-200 rounded px-3 py-1.5 mt-3 text-xs font-mono">
                Restart-Service DucksInARow
              </code>
            )}
          </div>
          <button
            onClick={() => window.location.reload()}
            className="inline-flex items-center gap-2 px-4 py-2 text-sm font-medium text-white
                       bg-certus-600 rounded-lg hover:bg-certus-700 transition-colors"
          >
            <RefreshCw className="h-4 w-4" />
            Reload
          </button>
        </div>
      </Card>
    );
  }

  return (
    <Card>
      <div className="flex items-center gap-2">
        <Globe className="h-4 w-4 text-certus-600" />
        <h3 className="text-sm font-semibold text-slate-900">External URL</h3>
      </div>
      <p className="text-sm text-slate-500">
        The base URL ACME clients use to reach this server. Changes are applied
        by a service restart.
      </p>

      {isLoading ? (
        <div className="flex items-center gap-2 text-sm text-slate-400 py-2">
          <Loader2 className="h-4 w-4 animate-spin" />
          Loading current configuration…
        </div>
      ) : isError ? (
        <div className="bg-red-50 border border-red-200 rounded-lg p-3 flex items-start gap-2">
          <AlertTriangle className="h-4 w-4 text-red-500 mt-0.5" />
          <p className="text-xs text-red-700">
            The current external URL configuration could not be loaded. Check the
            service log; a settings.json in the data directory that is not valid
            JSON must be fixed by hand.
          </p>
        </div>
      ) : (
        <>
          <dl className="text-sm space-y-1">
            <div className="flex gap-2">
              <dt className="text-slate-500 min-w-[130px]">Currently in effect:</dt>
              <dd className="text-slate-900 font-mono text-xs pt-0.5">
                {settings?.effectiveUrl ?? 'not configured'}
              </dd>
            </div>
            {settings?.restartPending && (
              <div className="flex gap-2">
                <dt className="text-slate-500 min-w-[130px]">Pending restart:</dt>
                <dd className="text-amber-700 font-mono text-xs pt-0.5">{settings.overlayUrl}</dd>
              </div>
            )}
          </dl>

          {/* An environment variable or command line value outranks the
              overlay: saving from here would change the file but never the
              effective URL. Say so instead of failing silently. */}
          {overriddenByOther && (
            <div className="bg-amber-50 border border-amber-200 rounded-lg p-3 flex items-start gap-2">
              <AlertTriangle className="h-4 w-4 text-amber-600 mt-0.5" />
              <p className="text-xs text-amber-800">
                The effective URL is set by an environment variable or command
                line argument, which outranks values saved here. Remove that
                override to manage the URL from this page.
              </p>
            </div>
          )}

          <div className="flex gap-2">
            <input
              type="url"
              value={currentUrl}
              onChange={(e) => handleUrlChange(e.target.value)}
              placeholder="https://certus.example.com:5001"
              className="flex-1 px-3 py-2 border border-slate-300 rounded-lg text-sm
                         placeholder:text-slate-400 focus:outline-none focus:ring-2
                         focus:ring-certus-500 focus:border-certus-500"
            />
            <button
              onClick={handleValidate}
              disabled={validating || saving || !currentUrl}
              className="inline-flex items-center gap-2 px-4 py-2 text-sm font-medium
                         text-certus-700 bg-certus-50 border border-certus-200 rounded-lg
                         hover:bg-certus-100 disabled:opacity-50 transition-colors"
            >
              {validating ? <Loader2 className="h-4 w-4 animate-spin" /> : 'Validate'}
            </button>
            <button
              onClick={() => handleSave(false)}
              disabled={saving || validating || !currentUrl || !dirty}
              className="inline-flex items-center gap-2 px-4 py-2 text-sm font-medium text-white
                         bg-certus-600 rounded-lg hover:bg-certus-700 disabled:opacity-50
                         transition-colors"
            >
              {saving ? <Loader2 className="h-4 w-4 animate-spin" /> : 'Save'}
            </button>
          </div>

          {/* Validation success. The copy states only what was actually checked. */}
          {validated && !probeFailed && (
            <div className="bg-emerald-50 border border-emerald-200 rounded-lg p-3 flex items-start gap-2">
              <CheckCircle2 className="h-4 w-4 text-emerald-600 mt-0.5" />
              <p className="text-xs text-emerald-800">
                {probe?.reachable
                  ? `The server answered at ${probe.dialedAuthority}.`
                  : probe && !probe.attempted
                    ? 'URL accepted. Reachability was not checked in demo mode.'
                    : 'URL accepted.'}
              </p>
            </div>
          )}

          {/* The probe could not reach the URL after Validate: warn and
              explain. Saving still runs its own probe and confirm flow. */}
          {probeFailed && !refusal && (
            <div className="bg-amber-50 border border-amber-200 rounded-lg p-3 flex items-start gap-2">
              <ShieldAlert className="h-4 w-4 text-amber-600 mt-0.5" />
              <div className="space-y-1">
                <p className="text-xs font-semibold text-amber-900">
                  The URL did not answer from the server
                </p>
                {probe?.failureDetail && (
                  <p className="text-xs text-amber-800">{probe.failureDetail}</p>
                )}
                <p className="text-xs text-amber-700">
                  It can still be correct when a reverse proxy or NAT rule forwards{' '}
                  <code className="font-mono">{probe?.dialedAuthority}</code> to the
                  service. Saving will ask for confirmation.
                </p>
              </div>
            </div>
          )}

          {/* The save probe refused the URL: show the outcome and offer the
              explicit confirm, mirroring the wizard. Never a hard block. */}
          {refusal && (
            <div className="bg-amber-50 border border-amber-200 rounded-lg p-3 flex items-start gap-2">
              <ShieldAlert className="h-4 w-4 text-amber-600 mt-0.5" />
              <div className="space-y-2">
                <p className="text-xs font-semibold text-amber-900">
                  The URL did not answer from the server
                </p>
                <p className="text-xs text-amber-800">
                  {refusal.probe?.failureDetail ?? refusal.message}
                </p>
                <button
                  onClick={handleConfirmAnyway}
                  disabled={saving}
                  className="inline-flex items-center gap-2 px-3 py-1.5 text-xs font-semibold
                             text-amber-900 bg-amber-100 border border-amber-300 rounded-lg
                             hover:bg-amber-200 disabled:opacity-50 transition-colors"
                >
                  Save with this URL anyway
                </button>
              </div>
            </div>
          )}

          {/* The URL answered but its TLS certificate does not validate. The
              backend carries this on the probe (not in warnings) so the
              wizard can offer enrollment there; here it is informational. */}
          {probe?.reachable && probe.certificateWarning && (
            <div className="bg-amber-50 border border-amber-200 rounded-lg p-3 flex items-start gap-2">
              <ShieldAlert className="h-4 w-4 text-amber-600 mt-0.5" />
              <p className="text-xs text-amber-800">{probe.certificateWarning}</p>
            </div>
          )}

          {warnings.length > 0 && (
            <div className="bg-amber-50 border border-amber-200 rounded-lg p-3 flex items-start gap-2">
              <AlertTriangle className="h-4 w-4 text-amber-600 mt-0.5" />
              <ul className="text-xs text-amber-700 list-disc list-inside space-y-0.5">
                {warnings.map((w, i) => (
                  <li key={i}>{w}</li>
                ))}
              </ul>
            </div>
          )}

          {error && (
            <div className="bg-red-50 border border-red-200 rounded-lg p-3 flex items-start gap-2">
              <AlertTriangle className="h-4 w-4 text-red-500 mt-0.5" />
              <p className="text-xs text-red-700">{error}</p>
            </div>
          )}

          <HttpsCertificateSection />
        </>
      )}
    </Card>
  );
}

function Card({ children }: { children: React.ReactNode }) {
  return (
    <div className="bg-white border border-slate-200 rounded-lg p-6 space-y-4">{children}</div>
  );
}
