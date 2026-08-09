import { useEffect, useRef, useState } from 'react';
import { CheckCircle2, Server, FileCheck2, Globe, Loader2, AlertTriangle, RefreshCw, Copy, KeyRound, ShieldAlert, ShieldCheck } from 'lucide-react';
import { completeSetup, waitForServiceRestart, type SetupUnreachableUrlResponse } from '@/api/setup';
import type { WizardState } from './SetupWizard';

interface ReviewStepProps {
  state: WizardState;
  onUpdate: (updates: Partial<WizardState>) => void;
  onComplete: () => void;
}

type Phase = 'review' | 'restarting' | 'completed' | 'manual-restart';

export function ReviewStep({ state, onUpdate, onComplete }: ReviewStepProps) {
  const [submitting, setSubmitting] = useState(false);
  const [error, setError] = useState<string | null>(null);
  const [phase, setPhase] = useState<Phase>('review');
  const [refusal, setRefusal] = useState<SetupUnreachableUrlResponse | null>(null);

  // Mirror the completion flow into the wizard state, so the shell's Back
  // button locks while completion is submitting or the service is restarting
  // (a step visited then could not load), and stays locked afterwards, when
  // the wizard endpoints are locked anyway.
  useEffect(() => {
    onUpdate({ reviewBusy: submitting || phase !== 'review' });
    // eslint-disable-next-line react-hooks/exhaustive-deps
  }, [submitting, phase]);

  const handleComplete = async (confirmUnreachable: boolean) => {
    setSubmitting(true);
    setError(null);
    // Clear a previous refusal too, so a failed retry does not show the old
    // refusal panel next to the new error message.
    setRefusal(null);

    try {
      const outcome = await completeSetup({
        caConnectionString: state.caConnectionString,
        enabledTemplates: state.selectedTemplates,
        externalUrl: state.externalUrl,
        allowedDomainsEnabled: state.allowedDomainsEnabled,
        allowedDomains: state.allowedDomains,
        // Either confirmed at the URL step, or confirmed just now in the
        // refusal panel below.
        confirmUnreachableExternalUrl:
          confirmUnreachable || state.urlConfirmedDespiteUnreachable,
      });

      if (outcome.kind === 'unreachableUrl') {
        // The completion probe found the URL unreachable and it was not
        // confirmed yet. Show the outcome and let the admin decide.
        setRefusal(outcome.refusal);
        return;
      }
      const result = outcome.result;

      if (result.restartScheduled) {
        // The service restarts itself to apply the configuration; wait for it
        // to come back before offering the dashboard.
        setPhase('restarting');
        const back = await waitForServiceRestart();
        setPhase(back ? 'completed' : 'manual-restart');
      } else if (result.setupCompleted) {
        // No self restart (development host or console run). The server
        // message says whether a manual restart is still needed.
        setPhase('completed');
      }
    } catch (err) {
      setError(err instanceof Error ? err.message : 'Setup failed');
    } finally {
      setSubmitting(false);
    }
  };

  if (phase === 'restarting') {
    return (
      <div className="space-y-6 text-center py-12">
        <RefreshCw className="h-12 w-12 text-certus-500 mx-auto animate-spin" />
        <div>
          <h2 className="text-xl font-bold text-ink">Applying configuration</h2>
          <p className="text-sm text-muted mt-2">
            The service is restarting to connect to your certificate authority.
            This page reconnects automatically; it usually takes a few seconds.
          </p>
        </div>
      </div>
    );
  }

  if (phase === 'manual-restart') {
    return (
      <div className="space-y-6 text-center py-8">
        <AlertTriangle className="h-12 w-12 text-amber-500 mx-auto" />
        <div>
          <h2 className="text-xl font-bold text-ink">Configuration saved, restart needed</h2>
          <p className="text-sm text-muted mt-2">
            The service did not come back in time. Restart it manually, then reload this page:
          </p>
          <code className="inline-block bg-sunken-strong border border-hairline rounded px-3 py-1.5 mt-3 text-xs font-mono">
            Restart-Service DucksInARow
          </code>
        </div>
        <button
          onClick={() => window.location.reload()}
          className="inline-flex items-center gap-2 px-6 py-2.5 text-sm font-medium text-white
                     bg-certus-600 rounded-lg hover:bg-certus-700 transition-colors"
        >
          <RefreshCw className="h-4 w-4" />
          Reload
        </button>
      </div>
    );
  }

  if (phase === 'completed') {
    // The saved ExternalUrl is not normalized; a trailing slash would put a
    // double slash in the path, which the ACME routes do not match.
    const directoryUrl = `${state.externalUrl.replace(/\/+$/, '')}/acme/${state.selectedTemplates[0] ?? 'WebServer'}/directory`;
    return (
      <div className="space-y-6 text-center py-8">
        <CheckCircle2 className="h-16 w-16 text-emerald-500 mx-auto" />
        <div>
          <h2 className="text-2xl font-bold text-ink">Setup Complete!</h2>
          <p className="text-sm text-muted mt-2">
            Ducks in a Row is configured and ready to issue certificates via ACME.
          </p>
        </div>

        <div className="bg-certus-50 dark:bg-certus-500/10 border border-certus-200 dark:border-certus-500/30 rounded-lg p-4 text-left max-w-md mx-auto">
          <h3 className="text-sm font-semibold text-certus-900 dark:text-certus-200 mb-2">Next steps:</h3>
          <ol className="text-sm text-certus-700 dark:text-certus-300 space-y-1.5 list-decimal list-inside">
            <li>
              Point ACME clients at your directory URL:
              <code className="block bg-surface border border-certus-200 dark:border-certus-500/30 rounded px-2 py-1 mt-1 text-xs font-mono">
                {directoryUrl}
              </code>
            </li>
            <li>Configure HTTP-01, DNS-01, or TLS-ALPN-01 challenge validation</li>
            <li>Request your first certificate!</li>
          </ol>
        </div>

        <RsaKeyNote
          directoryUrl={directoryUrl}
          keyAlgorithm={state.templateKeyAlgorithm}
          minimalKeySize={state.templateMinimalKeySize}
        />

        <button
          onClick={onComplete}
          className="inline-flex items-center gap-2 px-6 py-2.5 text-sm font-medium text-white
                     bg-certus-600 rounded-lg hover:bg-certus-700 transition-colors"
        >
          Go to Dashboard
        </button>
      </div>
    );
  }

  return (
    <div className="space-y-6">
      <div>
        <h2 className="text-xl font-bold text-ink">Review Configuration</h2>
        <p className="text-sm text-muted mt-1">
          Confirm your settings before completing setup.
        </p>
      </div>

      <div className="space-y-4">
        {/* CA Connection */}
        <div className="border border-hairline rounded-lg p-4">
          <div className="flex items-center gap-2 mb-2">
            <Server className="h-4 w-4 text-certus-600" />
            <h3 className="text-sm font-semibold text-ink">Certificate Authority</h3>
          </div>
          <dl className="text-sm space-y-1">
            <div className="flex gap-2">
              <dt className="text-muted min-w-[120px]">CA Name:</dt>
              <dd className="text-ink font-medium">{state.caName}</dd>
            </div>
            <div className="flex gap-2">
              <dt className="text-muted min-w-[120px]">DNS Name:</dt>
              <dd className="text-ink">{state.caDnsName}</dd>
            </div>
            <div className="flex gap-2">
              <dt className="text-muted min-w-[120px]">Connection:</dt>
              <dd className="text-ink font-mono text-xs">{state.caConnectionString}</dd>
            </div>
          </dl>
        </div>

        {/* Templates */}
        <div className="border border-hairline rounded-lg p-4">
          <div className="flex items-center gap-2 mb-2">
            <FileCheck2 className="h-4 w-4 text-certus-600" />
            <h3 className="text-sm font-semibold text-ink">
              Certificate Templates ({state.selectedTemplates.length})
            </h3>
          </div>
          <div className="flex flex-wrap gap-2">
            {state.selectedTemplates.map((name) => (
              <span
                key={name}
                className="inline-flex items-center px-2.5 py-1 rounded-md bg-certus-50 dark:bg-certus-500/10 text-certus-700 dark:text-certus-300 text-xs font-medium border border-certus-200 dark:border-certus-500/30"
              >
                {name}
              </span>
            ))}
          </div>
        </div>

        {/* Domain restriction */}
        <div className="border border-hairline rounded-lg p-4">
          <div className="flex items-center gap-2 mb-2">
            <ShieldCheck className="h-4 w-4 text-certus-600" />
            <h3 className="text-sm font-semibold text-ink">Domain Restriction</h3>
          </div>
          {state.allowedDomainsEnabled ? (
            <>
              <p className="text-sm text-ink">
                Certificates are issued only for these domains and their subdomains:
              </p>
              <div className="flex flex-wrap gap-2 mt-2">
                {state.allowedDomains.map((domain) => (
                  <span
                    key={domain}
                    className="inline-flex items-center px-2.5 py-1 rounded-md bg-certus-50 dark:bg-certus-500/10 text-certus-700 dark:text-certus-300 text-xs font-medium border border-certus-200 dark:border-certus-500/30"
                  >
                    {domain}
                  </span>
                ))}
              </div>
            </>
          ) : (
            <p className="text-sm text-ink">
              Off. ACME clients can order certificates for any name that
              passes challenge validation.
            </p>
          )}
        </div>

        {/* External URL */}
        <div className="border border-hairline rounded-lg p-4">
          <div className="flex items-center gap-2 mb-2">
            <Globe className="h-4 w-4 text-certus-600" />
            <h3 className="text-sm font-semibold text-ink">External URL</h3>
          </div>
          <p className="text-sm text-ink font-mono">{state.externalUrl}</p>
          <p className="text-xs text-muted mt-1">
            ACME directories will be available at {state.externalUrl}/acme/{'{template}'}/directory
          </p>
        </div>
      </div>

      {/* The completion probe found the URL unreachable: show the outcome
          and ask for an explicit confirmation. Never a hard block. */}
      {refusal && (
        <div className="bg-amber-50 dark:bg-amber-500/10 border border-amber-200 dark:border-amber-500/30 rounded-lg p-4 flex items-start gap-3">
          <ShieldAlert className="h-5 w-5 text-amber-600 mt-0.5" />
          <div className="space-y-2">
            <p className="text-sm font-semibold text-amber-900 dark:text-amber-200">
              The external URL did not answer from the server
            </p>
            <p className="text-sm text-amber-800 dark:text-amber-300">
              {refusal.probe?.failureDetail ?? refusal.message}
            </p>
            <p className="text-xs text-amber-700 dark:text-amber-300">
              It can still be correct when a reverse proxy or NAT rule forwards{' '}
              <code className="font-mono">{refusal.probe?.dialedAuthority ?? 'the advertised address'}</code>{' '}
              to the service. Go back to fix the URL, or complete setup with it as entered.
            </p>
            <button
              onClick={() => handleComplete(true)}
              disabled={submitting}
              className="inline-flex items-center gap-2 px-3 py-1.5 text-xs font-semibold
                         text-amber-900 dark:text-amber-200 bg-amber-100 dark:bg-amber-500/15 border border-amber-300 rounded-lg
                         hover:bg-amber-200 dark:bg-amber-500/25 disabled:opacity-50 transition-colors"
            >
              Complete with this URL anyway
            </button>
          </div>
        </div>
      )}

      {error && (
        <div className="bg-red-50 dark:bg-red-500/10 border border-red-200 dark:border-red-500/30 rounded-lg p-4 flex items-start gap-3">
          <AlertTriangle className="h-5 w-5 text-red-500 mt-0.5" />
          <p className="text-sm text-red-700 dark:text-red-300">{error}</p>
        </div>
      )}

      <button
        onClick={() => handleComplete(false)}
        disabled={submitting}
        className="w-full inline-flex items-center justify-center gap-2 px-6 py-3 text-sm font-semibold
                   text-white bg-certus-600 rounded-lg hover:bg-certus-700
                   disabled:opacity-50 transition-colors"
      >
        {submitting ? (
          <>
            <Loader2 className="h-4 w-4 animate-spin" />
            Completing Setup...
          </>
        ) : (
          <>
            <CheckCircle2 className="h-4 w-4" />
            Complete Setup
          </>
        )}
      </button>
    </div>
  );
}

// A template rejects any CSR whose key does not match its requirements; the
// CA answers "Denied by Policy Module" at finalize with no hint why. Warn
// here, before the first request, with a command that already carries the
// matching key flags — RSA by default (the default Web Server template is
// RSA only), an ECDSA variant when the template verifiably requires one.
// The command also carries -m, --agree-tos, and --no-eff-email so the first
// certbot run needs no interactive answers and skips the EFF mailing list
// question. When the Templates step could read the key requirements from
// AD, the note states them as fact instead of assuming the default.
function RsaKeyNote({
  directoryUrl,
  keyAlgorithm,
  minimalKeySize,
}: {
  directoryUrl: string;
  keyAlgorithm: string | null;
  minimalKeySize: number | null;
}) {
  const [copied, setCopied] = useState(false);
  const copyTimer = useRef<ReturnType<typeof setTimeout>>();

  useEffect(() => () => {
    if (copyTimer.current) clearTimeout(copyTimer.current);
  }, []);

  const algorithm = keyAlgorithm?.toUpperCase() ?? null;
  const isVerifiedRsa = algorithm === 'RSA';
  const isEcdsa = algorithm?.startsWith('ECDSA') ?? false;
  const rsaKeySize = minimalKeySize ?? 2048;

  // The ECDSA curve from the algorithm name suffix (ECDSA_P256 and friends),
  // or from the minimum key size when the name carries no curve.
  const curve = !isEcdsa
    ? null
    : algorithm!.endsWith('P384') ? 'P-384'
    : algorithm!.endsWith('P521') ? 'P-521'
    : algorithm!.endsWith('P256') ? 'P-256'
    : (minimalKeySize ?? 256) >= 521 ? 'P-521'
    : (minimalKeySize ?? 256) >= 384 ? 'P-384'
    : 'P-256';

  // A template with a verified algorithm we cannot write a certbot command
  // for gets a short note instead: DSA and ECDH algorithms always, and
  // ECDSA P-521 because certbot does not support that curve.
  if ((algorithm != null && !isVerifiedRsa && !isEcdsa) || curve === 'P-521') {
    return (
      <div className="bg-amber-50 dark:bg-amber-500/10 border border-amber-200 dark:border-amber-500/30 rounded-lg p-4 text-left max-w-md mx-auto">
        <div className="flex items-center gap-2 mb-2">
          <KeyRound className="h-4 w-4 text-amber-600" />
          <h3 className="text-sm font-semibold text-amber-900 dark:text-amber-200">Before requesting a certificate</h3>
        </div>
        <p className="text-sm text-amber-800 dark:text-amber-300">
          Your selected template requires <code className="bg-amber-100 dark:bg-amber-500/15 px-1 rounded text-xs">{keyAlgorithm}</code>{' '}
          keys{minimalKeySize ? ` (minimum ${minimalKeySize} bits)` : ''}. Configure your ACME
          client to request a matching key type, or the CA will reject the request with{' '}
          <code className="bg-amber-100 dark:bg-amber-500/15 px-1 rounded text-xs">Denied by Policy Module</code>.
          {curve === 'P-521' && (
            <> certbot does not support P-521 keys; use a client that does, for example acme.sh.</>
          )}
        </p>
      </div>
    );
  }

  const commandPrefix =
    `certbot certonly --standalone --server ${directoryUrl} -d <your host> ` +
    '-m <your-email@example.com> --agree-tos --no-eff-email';
  const curveParam = curve === 'P-384' ? 'secp384r1' : 'secp256r1';
  const command = isEcdsa
    ? `${commandPrefix} --key-type ecdsa --elliptic-curve ${curveParam}`
    : `${commandPrefix} --key-type rsa --rsa-key-size ${rsaKeySize}`;

  const handleCopy = async () => {
    try {
      if (!navigator.clipboard) throw new Error('Clipboard unavailable');
      await navigator.clipboard.writeText(command);
      setCopied(true);
      if (copyTimer.current) clearTimeout(copyTimer.current);
      copyTimer.current = setTimeout(() => setCopied(false), 2000);
    } catch {
      // Clipboard API is unavailable (non-secure context) or was denied; fail quietly.
    }
  };

  return (
    <div className="bg-amber-50 dark:bg-amber-500/10 border border-amber-200 dark:border-amber-500/30 rounded-lg p-4 text-left max-w-md mx-auto">
      <div className="flex items-center gap-2 mb-2">
        <KeyRound className="h-4 w-4 text-amber-600" />
        <h3 className="text-sm font-semibold text-amber-900 dark:text-amber-200">Before requesting a certificate</h3>
      </div>
      <p className="text-sm text-amber-800 dark:text-amber-300">
        {isEcdsa ? (
          <>
            Your selected template requires ECDSA keys on curve {curve}. Your ACME client
            must request one, or the CA will reject the request with{' '}
          </>
        ) : isVerifiedRsa ? (
          <>
            Your selected template requires an RSA key
            {minimalKeySize ? ` of at least ${minimalKeySize} bits` : ''}. Your ACME client
            must request one, or the CA will reject the request with{' '}
          </>
        ) : (
          <>
            If your selected template uses an RSA key (the default does), your ACME
            client must request an RSA key, or the CA will reject the request with{' '}
          </>
        )}
        <code className="bg-amber-100 dark:bg-amber-500/15 px-1 rounded text-xs">Denied by Policy Module</code>.
        Example (certbot):
      </p>
      <div className="flex items-start gap-2 mt-2">
        <code className="flex-1 bg-surface border border-amber-200 dark:border-amber-500/30 rounded px-2 py-1 text-xs font-mono break-all">
          {command}
        </code>
        <button
          onClick={handleCopy}
          className="mt-1 inline-flex items-center text-amber-500 hover:text-amber-700 dark:text-amber-300"
          title="Copy to clipboard"
          aria-label="Copy certbot command"
        >
          {copied ? (
            <CheckCircle2 className="h-3.5 w-3.5 text-emerald-500" />
          ) : (
            <Copy className="h-3.5 w-3.5" />
          )}
        </button>
      </div>
      <p className="text-xs text-amber-700 dark:text-amber-300 mt-1">
        Replace the host and email placeholders before running.
      </p>
      <p className="text-xs text-amber-700 dark:text-amber-300 mt-2">
        {isEcdsa ? (
          curve === 'P-384' ? (
            <>
              Other clients: lego <code>--key-type ec384</code>, acme.sh{' '}
              <code>--keylength ec-384</code>, dehydrated <code>KEY_ALGO="secp384r1"</code>.
            </>
          ) : (
            <>
              Other clients: lego <code>--key-type ec256</code>, acme.sh{' '}
              <code>--keylength ec-256</code>, dehydrated <code>KEY_ALGO="prime256v1"</code>.
            </>
          )
        ) : (
          <>
            Other clients: lego <code>--key-type rsa{rsaKeySize}</code>, acme.sh{' '}
            <code>--keylength {rsaKeySize}</code>, dehydrated <code>KEY_ALGO="rsa"</code>.
          </>
        )}
      </p>
    </div>
  );
}
