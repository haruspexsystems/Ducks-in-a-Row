import { useEffect, useRef, useState } from 'react';
import {
  Globe,
  CheckCircle2,
  AlertTriangle,
  Loader2,
  ShieldAlert,
  ShieldCheck,
  BadgeCheck,
  ExternalLink,
} from 'lucide-react';
import {
  validateExternalUrl,
  provisionTlsCertificate,
  applyTlsCertificate,
  discardTlsCertificate,
  waitForServiceUp,
  type UrlProbeResult,
  type TlsProvisionResult,
} from '@/api/setup';
import type { WizardState } from './SetupWizard';

interface ExternalUrlStepProps {
  state: WizardState;
  onUpdate: (updates: Partial<WizardState>) => void;
}

/**
 * Where the one click certificate flow stands. The flow is advisory: any
 * failure leaves the wizard fully usable on the self signed certificate.
 */
type CertPhase =
  | 'idle'
  | 'enrolling'
  | 'mismatch'
  | 'restarting'
  | 'revalidating'
  | 'installed'
  | 'continueElsewhere'
  | 'manualRestart';

/**
 * How long the cross origin continue link stays locked after the install
 * call schedules the restart, so a quick click does not land on the old
 * self signed certificate. A fixed countdown rather than a readiness
 * probe: our own Content Security Policy sends connect-src 'self', so the
 * browser rejects any cross origin fetch from this page before it leaves
 * the machine, and after the restart this origin cannot answer TLS for
 * this browser either. Navigation is the only cross origin act the policy
 * permits, so the unlock is timed. The observed restart is a few seconds;
 * this budget covers slower machines.
 */
const CONTINUE_LINK_UNLOCK_SECONDS = 15;

interface CertMismatch {
  thumbprint: string;
  issuedNames: string[];
}

export function ExternalUrlStep({ state, onUpdate }: ExternalUrlStepProps) {
  const [validating, setValidating] = useState(false);
  const [error, setError] = useState<string | null>(null);
  const [warnings, setWarnings] = useState<string[]>([]);
  const [probe, setProbe] = useState<UrlProbeResult | null>(null);
  const [certPhase, setCertPhase] = useState<CertPhase>('idle');
  const [certMessage, setCertMessage] = useState<string | null>(null);
  const [mismatch, setMismatch] = useState<CertMismatch | null>(null);
  const [continueUrl, setContinueUrl] = useState<string | null>(null);
  const [continueCountdown, setContinueCountdown] = useState(CONTINUE_LINK_UNLOCK_SECONDS);

  // Runs the unlock countdown whenever the continue panel is showing. The
  // cleanup tears the interval down on a phase change or unmount, so an
  // edited URL or a re-enroll restarts the countdown naturally.
  useEffect(() => {
    if (certPhase !== 'continueElsewhere') return;
    setContinueCountdown(CONTINUE_LINK_UNLOCK_SECONDS);
    const timer = setInterval(() => {
      setContinueCountdown((s) => {
        if (s <= 1) {
          clearInterval(timer);
          return 0;
        }
        return s - 1;
      });
    }, 1000);
    return () => clearInterval(timer);
  }, [certPhase]);

  // Mirror the certificate flow into the wizard state the shell's navigation
  // reads. During the busy phases every fetch from this page fails (the
  // service is down or restarting), and in continueElsewhere this origin
  // never answers again, so the shell locks Back and replaces Next with the
  // continue navigation. continueUnlocked resets on every phase change and
  // is granted again below only when the countdown runs out, so a re-entry
  // after a completed countdown starts locked.
  useEffect(() => {
    onUpdate({
      urlStepBusy:
        certPhase === 'enrolling' ||
        certPhase === 'restarting' ||
        certPhase === 'revalidating',
      continueElsewhereUrl: certPhase === 'continueElsewhere' ? continueUrl : null,
      continueUnlocked: false,
    });
    // eslint-disable-next-line react-hooks/exhaustive-deps
  }, [certPhase, continueUrl]);

  useEffect(() => {
    if (certPhase === 'continueElsewhere' && continueCountdown === 0) {
      onUpdate({ continueUnlocked: true });
    }
    // eslint-disable-next-line react-hooks/exhaustive-deps
  }, [certPhase, continueCountdown]);

  const handleValidate = async () => {
    if (!state.externalUrl) return;

    setValidating(true);
    setError(null);
    setWarnings([]);
    setProbe(null);

    try {
      // The probe targets the ACME directory of the first selected template,
      // the same URL the success copy tells clients to use.
      const result = await validateExternalUrl(state.externalUrl, state.selectedTemplates[0]);

      if (!result.valid) {
        setError(result.errorMessage ?? 'Invalid URL');
        onUpdate({ urlValidated: false, urlConfirmedDespiteUnreachable: false });
        return;
      }

      setWarnings(result.warnings ?? []);
      const probeResult = result.probe ?? null;
      setProbe(probeResult);

      if (probeResult && probeResult.attempted && !probeResult.reachable) {
        // The server could not reach the URL. Not a hard stop: the admin can
        // confirm below (reverse proxy and hairpin NAT deployments are
        // legitimately unreachable from the server itself).
        onUpdate({ urlValidated: false, urlConfirmedDespiteUnreachable: false });
      } else {
        onUpdate({ urlValidated: true, urlConfirmedDespiteUnreachable: false });
      }
    } catch (err) {
      setError(err instanceof Error ? err.message : 'Validation failed');
      onUpdate({ urlValidated: false, urlConfirmedDespiteUnreachable: false });
    } finally {
      setValidating(false);
    }
  };

  const handleConfirmAnyway = () => {
    onUpdate({ urlValidated: true, urlConfirmedDespiteUnreachable: true });
  };

  // A certificate was already enrolled and configured before this page load
  // (the wizard resumed after the cross origin continue hop, or an F5 during
  // the mid wizard restart). Show it as installed instead of offering to
  // enroll again, and validate the URL against the restarted service so
  // urlValidated is earned, not assumed. Gated on tlsCertificateInstalled,
  // a real store lookup from the backend — a thumbprint recorded in the
  // overlay with no matching certificate left in the store (manual cleanup,
  // a restore) must not claim "installed" from a stale pointer alone.
  const resumedWithCertificate = useRef(false);
  useEffect(() => {
    if (
      resumedWithCertificate.current ||
      !state.tlsCertificateThumbprint ||
      !state.tlsCertificateInstalled ||
      !state.externalUrl ||
      state.urlValidated ||
      certPhase !== 'idle'
    ) {
      return;
    }
    resumedWithCertificate.current = true;
    setCertPhase('installed');
    void handleValidate();
    // eslint-disable-next-line react-hooks/exhaustive-deps
  }, []);

  const handleUrlChange = (url: string) => {
    onUpdate({ externalUrl: url, urlValidated: false, urlConfirmedDespiteUnreachable: false });
    setError(null);
    setWarnings([]);
    setProbe(null);
    setCertPhase('idle');
    setCertMessage(null);
    setMismatch(null);
    setContinueUrl(null);
  };

  // ── One click TLS certificate ────────────────────────────────────────

  const handleGetCertificate = async () => {
    if (!state.externalUrl || state.selectedTemplates.length === 0) return;
    setCertPhase('enrolling');
    setCertMessage(null);

    try {
      const result = await provisionTlsCertificate(
        state.caConnectionString,
        state.selectedTemplates[0],
        state.externalUrl,
      );
      await handleProvisionResult(result);
    } catch (err) {
      setCertMessage(err instanceof Error ? err.message : 'Certificate enrollment failed');
      setCertPhase('idle');
    }
  };

  const handleProvisionResult = async (result: TlsProvisionResult) => {
    if (result.outcome === 'sanMismatch') {
      setMismatch({ thumbprint: result.thumbprint, issuedNames: result.issuedNames });
      setCertPhase('mismatch');
      return;
    }

    if (result.outcome !== 'installed') {
      // pending / denied / failed: the message carries the exact fix.
      setCertMessage(result.message ?? 'Certificate enrollment failed');
      setCertPhase('idle');
      return;
    }

    if (result.currentHostCovered === false && result.continueUrl) {
      // The new certificate does not cover the host this page is on. After
      // the restart every fetch from here fails the TLS handshake, so hand
      // the admin the link to continue at the covered origin. The wizard
      // there prefills from the draft the server saved before restarting.
      // Reset the countdown here as well as in the effect: the effect runs
      // after paint, and a re-entry after a completed countdown must not
      // show the link unlocked for that first frame.
      setContinueUrl(result.continueUrl);
      setContinueCountdown(CONTINUE_LINK_UNLOCK_SECONDS);
      setCertPhase('continueElsewhere');
      return;
    }

    if (!result.restartScheduled) {
      // Console or development run: the service cannot restart itself.
      setCertPhase('manualRestart');
      return;
    }

    setCertPhase('restarting');
    const up = await waitForServiceUp();
    if (!up) {
      setCertMessage(
        'The service did not come back in time. Restart it manually (Restart-Service ' +
          'DucksInARow), then validate the URL again.',
      );
      setCertPhase('idle');
      return;
    }

    setCertPhase('revalidating');
    await handleValidate();
    setCertPhase('installed');
  };

  const handleApplyMismatched = async () => {
    if (!mismatch) return;
    const applied = mismatch;
    setCertPhase('enrolling');
    setCertMessage(null);
    try {
      const result = await applyTlsCertificate(
        state.caConnectionString,
        state.selectedTemplates[0],
        state.externalUrl,
        applied.thumbprint,
      );
      setMismatch(null);
      await handleProvisionResult(result);
    } catch (err) {
      setCertMessage(err instanceof Error ? err.message : 'Applying the certificate failed');
      setCertPhase('mismatch');
    }
  };

  const handleDiscardMismatched = async () => {
    if (!mismatch) return;
    try {
      await discardTlsCertificate(mismatch.thumbprint);
    } catch {
      // Best effort: a leftover store entry is harmless and visible in certlm.msc.
    }
    setMismatch(null);
    setCertPhase('idle');
  };

  const probeFailed = probe !== null && probe.attempted && !probe.reachable;
  // The certificate warning only makes sense when the URL answered: an
  // unreachable URL gets the reachability panel instead.
  const certificateWarning = probe?.reachable ? (probe.certificateWarning ?? null) : null;
  const selectedTemplate = state.selectedTemplates[0];
  const certBusy =
    certPhase === 'enrolling' || certPhase === 'restarting' || certPhase === 'revalidating';
  // Once the continue panel shows, this origin is done for: editing the URL
  // resets the phase to idle, which would unlock Next against a page whose
  // every fetch fails. Freeze the input instead; the panel says where to go.
  const frozen = certPhase === 'continueElsewhere';

  // Trailing slashes are stripped like ReviewStep does for the real
  // directory URL, so the preview never shows a double slash.
  const directoryPreview = `${(state.externalUrl || 'https://certus.example.com').replace(/\/+$/, '')}/acme/${
    selectedTemplate ?? 'WebServer'
  }/directory`;

  return (
    <div className="space-y-6">
      <div>
        <h2 className="text-xl font-bold text-ink">External URL</h2>
        <p className="text-sm text-muted mt-1">
          This is the base URL that ACME clients will use to reach the Ducks in a Row server.
          It must be reachable from every machine that needs to request certificates.
        </p>
      </div>

      <div className="bg-sunken border border-hairline rounded-lg p-4">
        <div className="flex items-start gap-3">
          <Globe className="h-5 w-5 text-faint mt-0.5" />
          <div className="text-sm text-ink-soft space-y-1">
            <p>ACME clients will construct directory URLs like:</p>
            <code className="block bg-surface border border-hairline rounded px-3 py-1.5 text-xs font-mono text-certus-700 dark:text-certus-300 mt-1">
              {directoryPreview}
            </code>
            <p className="text-xs text-muted mt-2">
              Use HTTPS for production, and include the port. The service listens on 5001 for
              HTTPS (5000 for HTTP) instead of 443, because IIS and the ADCS web roles often
              occupy 443 on Windows servers and a port collision would stop the service from
              starting. The ports can be changed under Kestrel:Endpoints in appsettings.json;
              update the firewall rules to match.
            </p>
          </div>
        </div>
      </div>

      <div className="space-y-3">
        <label className="block text-sm font-medium text-ink-soft">
          Server URL
        </label>
        <div className="flex gap-2">
          <input
            type="url"
            value={state.externalUrl}
            onChange={(e) => handleUrlChange(e.target.value)}
            disabled={frozen}
            placeholder="https://certus.example.com:5001"
            className="flex-1 px-3 py-2 border border-hairline-strong rounded-lg text-sm
                       placeholder:text-faint focus:outline-none focus:ring-2
                       focus:ring-certus-500 focus:border-certus-500
                       disabled:opacity-50 disabled:cursor-not-allowed"
          />
          <button
            onClick={handleValidate}
            disabled={validating || certBusy || frozen || !state.externalUrl}
            className="inline-flex items-center gap-2 px-4 py-2 text-sm font-medium text-white
                       bg-certus-600 rounded-lg hover:bg-certus-700 disabled:opacity-50 transition-colors"
          >
            {validating ? (
              <Loader2 className="h-4 w-4 animate-spin" />
            ) : (
              'Validate'
            )}
          </button>
        </div>
      </div>

      {/* Validation success. The copy states only what was actually checked. */}
      {state.urlValidated && !probeFailed && (
        <div className="bg-emerald-50 dark:bg-emerald-500/10 border border-emerald-200 dark:border-emerald-500/30 rounded-lg p-4 flex items-start gap-3">
          <CheckCircle2 className="h-5 w-5 text-emerald-600 mt-0.5" />
          <div>
            <p className="text-sm font-semibold text-emerald-900 dark:text-emerald-200">
              {probe?.reachable ? 'Server reachable' : 'URL accepted'}
            </p>
            <p className="text-xs text-emerald-700 dark:text-emerald-300 mt-0.5">
              {probe?.reachable
                ? `The server answered at ${probe.dialedAuthority}. `
                : probe && !probe.attempted
                  ? 'Reachability was not checked in demo mode. '
                  : ''}
              ACME clients should target:{' '}
              <code className="font-mono">{state.externalUrl}/acme/{'{template}'}/directory</code>
            </p>
          </div>
        </div>
      )}

      {/* The probe could not reach the URL: warn, explain, offer an explicit
          confirm. Never a hard block. */}
      {probeFailed && (
        <div className="bg-amber-50 dark:bg-amber-500/10 border border-amber-200 dark:border-amber-500/30 rounded-lg p-4 flex items-start gap-3">
          <ShieldAlert className="h-5 w-5 text-amber-600 mt-0.5" />
          <div className="space-y-2">
            <p className="text-sm font-semibold text-amber-900 dark:text-amber-200">
              The URL did not answer from the server
            </p>
            <p className="text-sm text-amber-800 dark:text-amber-300">{probe?.failureDetail}</p>
            <p className="text-xs text-amber-700 dark:text-amber-300">
              This usually means the URL is missing the port the service listens on.
              It can still be correct when a reverse proxy or NAT rule forwards{' '}
              <code className="font-mono">{probe?.dialedAuthority}</code> to the service,
              because such setups can be unreachable from the server itself.
            </p>
            {state.urlValidated ? (
              <p className="text-xs font-semibold text-amber-900 dark:text-amber-200">
                Confirmed. Setup will use this URL as entered.
              </p>
            ) : (
              <button
                onClick={handleConfirmAnyway}
                className="inline-flex items-center gap-2 px-3 py-1.5 text-xs font-semibold
                           text-amber-900 dark:text-amber-200 bg-amber-100 dark:bg-amber-500/15 border border-amber-300 rounded-lg
                           hover:bg-amber-200 dark:bg-amber-500/25 transition-colors"
              >
                Use this URL anyway
              </button>
            )}
          </div>
        </div>
      )}

      {/* TLS certificate: the URL answered but its certificate does not
          validate (the shipped self signed fallback does not). Offer to
          enroll a real one from the CA with the selected template. */}
      {certificateWarning && certPhase === 'idle' && (
        <div className="bg-amber-50 dark:bg-amber-500/10 border border-amber-200 dark:border-amber-500/30 rounded-lg p-4 flex items-start gap-3">
          <ShieldAlert className="h-5 w-5 text-amber-600 mt-0.5" />
          <div className="space-y-2">
            <p className="text-sm font-semibold text-amber-900 dark:text-amber-200">
              The server's TLS certificate is not trusted
            </p>
            <p className="text-sm text-amber-800 dark:text-amber-300">{certificateWarning}</p>
            <p className="text-xs text-amber-700 dark:text-amber-300">
              Ducks in a Row can request a certificate for{' '}
              <code className="font-mono">{new URL(state.externalUrl || 'https://x').hostname}</code>{' '}
              from your CA right now, install it, and restart itself to serve it. This also
              proves the template works end to end: ACME requests enroll with the same
              service account.
            </p>
            <button
              onClick={handleGetCertificate}
              disabled={!selectedTemplate}
              className="inline-flex items-center gap-2 px-3 py-1.5 text-xs font-semibold
                         text-white bg-certus-600 rounded-lg hover:bg-certus-700
                         disabled:opacity-50 transition-colors"
            >
              <ShieldCheck className="h-3.5 w-3.5" />
              Get a certificate using the {selectedTemplate} template
            </button>
            {certMessage && (
              <p className="text-xs text-red-700 dark:text-red-300 whitespace-pre-line">{certMessage}</p>
            )}
          </div>
        </div>
      )}

      {/* Certificate flow progress */}
      {certBusy && (
        <div className="bg-sunken border border-hairline rounded-lg p-4 flex items-start gap-3">
          <Loader2 className="h-5 w-5 text-certus-500 mt-0.5 animate-spin" />
          <div>
            <p className="text-sm font-semibold text-ink">
              {certPhase === 'enrolling' && 'Requesting a certificate from the CA'}
              {certPhase === 'restarting' && 'Certificate installed, the service is restarting'}
              {certPhase === 'revalidating' && 'Service is back, checking the URL again'}
            </p>
            <p className="text-xs text-muted mt-0.5">
              {certPhase === 'restarting'
                ? 'This page reconnects automatically; it usually takes a few seconds.'
                : 'This should only take a moment.'}
            </p>
          </div>
        </div>
      )}

      {/* Issued certificate does not cover the external URL host (template
          builds the subject from AD). Explicit decision, never automatic. */}
      {certPhase === 'mismatch' && mismatch && (
        <div className="bg-amber-50 dark:bg-amber-500/10 border border-amber-200 dark:border-amber-500/30 rounded-lg p-4 flex items-start gap-3">
          <ShieldAlert className="h-5 w-5 text-amber-600 mt-0.5" />
          <div className="space-y-2">
            <p className="text-sm font-semibold text-amber-900 dark:text-amber-200">
              The issued certificate does not match the server URL
            </p>
            <p className="text-sm text-amber-800 dark:text-amber-300">
              The CA issued a certificate for{' '}
              <code className="font-mono">{mismatch.issuedNames.join(', ') || '(no names)'}</code>,
              but the server URL host is{' '}
              <code className="font-mono">{new URL(state.externalUrl || 'https://x').hostname}</code>.
              ACME clients checking that URL would reject it.
            </p>
            <p className="text-xs text-amber-700 dark:text-amber-300">
              This happens when the template builds the subject from Active Directory. Either
              change the server URL to match the issued name, or select "Supply in the request"
              on the Subject Name tab of the template in the Certificate Templates console and
              try again.
            </p>
            <div className="flex gap-2">
              <button
                onClick={handleApplyMismatched}
                className="inline-flex items-center gap-2 px-3 py-1.5 text-xs font-semibold
                           text-amber-900 dark:text-amber-200 bg-amber-100 dark:bg-amber-500/15 border border-amber-300 rounded-lg
                           hover:bg-amber-200 dark:bg-amber-500/25 transition-colors"
              >
                Install it anyway
              </button>
              <button
                onClick={handleDiscardMismatched}
                className="inline-flex items-center gap-2 px-3 py-1.5 text-xs font-semibold
                           text-ink-soft bg-surface border border-hairline-strong rounded-lg
                           hover:bg-sunken transition-colors"
              >
                Discard the certificate
              </button>
            </div>
            {certMessage && (
              <p className="text-xs text-red-700 dark:text-red-300 whitespace-pre-line">{certMessage}</p>
            )}
          </div>
        </div>
      )}

      {/* The new certificate does not cover the host this page is on; after
          the restart this origin stops answering TLS for this browser. */}
      {certPhase === 'continueElsewhere' && continueUrl && (
        <div className="bg-certus-50 dark:bg-certus-500/10 border border-certus-200 dark:border-certus-500/30 rounded-lg p-4 flex items-start gap-3">
          <ExternalLink className="h-5 w-5 text-certus-600 mt-0.5" />
          <div className="space-y-2">
            <p className="text-sm font-semibold text-certus-900 dark:text-certus-200">
              Certificate installed, continue at the server URL
            </p>
            <p className="text-sm text-certus-800 dark:text-certus-300">
              The service is restarting with the new certificate. It does not cover{' '}
              <code className="font-mono">{window.location.hostname}</code>, so this page will
              lose its connection. Your progress is saved; continue setup at:
            </p>
            {continueCountdown > 0 ? (
              <span
                aria-disabled="true"
                className="inline-flex items-center gap-2 px-3 py-1.5 text-xs font-semibold
                           text-white bg-certus-400 rounded-lg cursor-not-allowed select-none"
              >
                {continueUrl}
              </span>
            ) : (
              <a
                href={continueUrl}
                className="inline-flex items-center gap-2 px-3 py-1.5 text-xs font-semibold
                           text-white bg-certus-600 rounded-lg hover:bg-certus-700 transition-colors"
              >
                <ExternalLink className="h-3.5 w-3.5" />
                {continueUrl}
              </a>
            )}
            {continueCountdown > 0 ? (
              <p className="text-xs text-certus-700 dark:text-certus-300">
                The service is restarting. The link unlocks in {continueCountdown}s.
              </p>
            ) : (
              <p className="text-xs text-certus-700 dark:text-certus-300">
                The service should be back now. If the page does not answer, wait a few
                seconds and try again. Your progress is saved.
              </p>
            )}
            <p className="text-xs text-certus-700 dark:text-certus-300">
              If the browser warns about the certificate at the new address, the machine you
              are browsing from does not trust your CA root certificate yet. Domain machines
              receive it through Group Policy (run{' '}
              <code className="font-mono">gpupdate /force</code> to refresh now). After setup
              completes you can also download the root from Settings, CA certificates.
            </p>
          </div>
        </div>
      )}

      {/* Console/development run: installed but the service cannot restart itself. */}
      {certPhase === 'manualRestart' && (
        <div className="bg-amber-50 dark:bg-amber-500/10 border border-amber-200 dark:border-amber-500/30 rounded-lg p-4 flex items-start gap-3">
          <AlertTriangle className="h-5 w-5 text-amber-600 mt-0.5" />
          <div>
            <p className="text-sm font-semibold text-amber-900 dark:text-amber-200">
              Certificate installed, restart needed
            </p>
            <p className="text-xs text-amber-700 dark:text-amber-300 mt-0.5">
              The service could not restart itself. Restart it manually
              (<code className="font-mono">Restart-Service DucksInARow</code>), then validate
              the URL again.
            </p>
          </div>
        </div>
      )}

      {/* Certificate flow finished and the URL was re validated. */}
      {certPhase === 'installed' && (
        <div className="bg-emerald-50 dark:bg-emerald-500/10 border border-emerald-200 dark:border-emerald-500/30 rounded-lg p-4 flex items-start gap-3">
          <BadgeCheck className="h-5 w-5 text-emerald-600 mt-0.5" />
          <div>
            <p className="text-sm font-semibold text-emerald-900 dark:text-emerald-200">
              Certificate installed and in use
            </p>
            <p className="text-xs text-emerald-700 dark:text-emerald-300 mt-0.5">
              {certificateWarning
                ? 'The service restarted with the new certificate, but it still does not ' +
                  'validate from the server itself — check that this machine trusts your ' +
                  'CA’s root certificate.'
                : 'The service restarted and now serves the certificate issued by your CA.'}
            </p>
          </div>
        </div>
      )}

      {/* Warnings */}
      {warnings.length > 0 && (
        <div className="bg-amber-50 dark:bg-amber-500/10 border border-amber-200 dark:border-amber-500/30 rounded-lg p-4 flex items-start gap-3">
          <AlertTriangle className="h-5 w-5 text-amber-600 mt-0.5" />
          <div>
            <p className="text-sm font-semibold text-amber-900 dark:text-amber-200">Warnings</p>
            <ul className="text-sm text-amber-700 dark:text-amber-300 mt-1 list-disc list-inside">
              {warnings.map((w, i) => <li key={i}>{w}</li>)}
            </ul>
          </div>
        </div>
      )}

      {/* Error */}
      {error && (
        <div className="bg-red-50 dark:bg-red-500/10 border border-red-200 dark:border-red-500/30 rounded-lg p-4 flex items-start gap-3">
          <AlertTriangle className="h-5 w-5 text-red-500 mt-0.5" />
          <p className="text-sm text-red-700 dark:text-red-300">{error}</p>
        </div>
      )}
    </div>
  );
}
