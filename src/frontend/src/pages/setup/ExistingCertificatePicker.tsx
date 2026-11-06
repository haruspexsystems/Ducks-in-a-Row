import { useEffect, useState } from 'react';
import { Loader2, RefreshCw, ShieldAlert, ShieldCheck } from 'lucide-react';
import {
  chooseExistingCertificate,
  fetchExistingCertificates,
  keepSelfSignedCertificate,
  type ExistingCertificate,
  type TlsProvisionResult,
} from '@/api/setup';

/** The radio value for keeping the generated self signed certificate. */
const SELF_SIGNED = 'self-signed';

interface ExistingCertificatePickerProps {
  caConnectionString: string;
  externalUrl: string;
  /** The probe's notice that the certificate served now does not validate, if any. */
  certificateWarning: string | null;
  /** A certificate was recorded; the restart and continue handling belong to the step. */
  onRecorded: (result: TlsProvisionResult) => Promise<void>;
  /** An earlier pick was cleared, and the service restarts to serve the self signed one. */
  onSelfSignedRestored: (restartScheduled: boolean) => Promise<void>;
}

/**
 * The monitor mode External URL step's certificate choice (issue #471). Monitor
 * mode never enrols the server's own certificate, so the choice is a certificate
 * already in this server's machine store, an autoenrolled one typically, or the
 * self signed certificate the service generates. The server lists only
 * certificates it could serve, and decides that again when one is chosen.
 */
export function ExistingCertificatePicker({
  caConnectionString,
  externalUrl,
  certificateWarning,
  onRecorded,
  onSelfSignedRestored,
}: ExistingCertificatePickerProps) {
  const [certificates, setCertificates] = useState<ExistingCertificate[] | null>(null);
  const [externalHost, setExternalHost] = useState('');
  const [configured, setConfigured] = useState<string | null>(null);
  const [loading, setLoading] = useState(true);
  const [loadError, setLoadError] = useState<string | null>(null);
  const [reloads, setReloads] = useState(0);
  const [choice, setChoice] = useState<string>(SELF_SIGNED);
  const [mismatchNames, setMismatchNames] = useState<string[] | null>(null);
  const [busy, setBusy] = useState(false);
  const [message, setMessage] = useState<string | null>(null);

  useEffect(() => {
    setLoading(true);
    setLoadError(null);
    fetchExistingCertificates(externalUrl)
      .then((data) => {
        setCertificates(data.certificates);
        setExternalHost(data.externalHost);
        const current = data.certificates.find((c) => c.configured);
        setConfigured(current?.thumbprint ?? null);
        setChoice(current?.thumbprint ?? SELF_SIGNED);
      })
      .catch((err: unknown) =>
        setLoadError(err instanceof Error ? err.message : 'The certificates could not be listed'),
      )
      .finally(() => setLoading(false));
  }, [externalUrl, reloads]);

  const choose = (value: string) => {
    setChoice(value);
    setMismatchNames(null);
    setMessage(null);
  };

  const handleUse = async (acceptNameMismatch: boolean) => {
    setBusy(true);
    setMessage(null);
    try {
      const outcome = await chooseExistingCertificate({
        caConnectionString,
        externalUrl,
        thumbprint: choice,
        acceptNameMismatch,
      });
      if (outcome.kind === 'nameMismatch') {
        setMismatchNames(outcome.names);
        return;
      }
      setMismatchNames(null);
      await onRecorded(outcome.result);
    } catch (err) {
      setMessage(err instanceof Error ? err.message : 'The certificate could not be used');
    } finally {
      setBusy(false);
    }
  };

  const handleKeepSelfSigned = async () => {
    setBusy(true);
    setMessage(null);
    try {
      const result = await keepSelfSignedCertificate(caConnectionString, externalUrl);
      if (result.outcome === 'selfSigned') {
        await onSelfSignedRestored(result.restartScheduled);
      } else {
        setMessage('Nothing to change: the service already serves its self signed certificate.');
      }
    } catch (err) {
      setMessage(err instanceof Error ? err.message : 'The change could not be made');
    } finally {
      setBusy(false);
    }
  };

  const keepingSelfSigned = choice === SELF_SIGNED;
  const unchanged = keepingSelfSigned ? configured === null : choice === configured;

  return (
    <div
      className={`rounded-lg p-4 flex items-start gap-3 border ${
        certificateWarning
          ? 'bg-amber-50 dark:bg-amber-500/10 border-amber-200 dark:border-amber-500/30'
          : 'bg-sunken border-hairline'
      }`}
    >
      {certificateWarning ? (
        <ShieldAlert className="h-5 w-5 text-amber-600 mt-0.5 shrink-0" />
      ) : (
        <ShieldCheck className="h-5 w-5 text-certus-600 mt-0.5 shrink-0" />
      )}
      <div className="space-y-3 flex-1 min-w-0">
        <div className="space-y-1">
          <p className="text-sm font-semibold text-ink">HTTPS certificate</p>
          {certificateWarning && (
            <p className="text-sm text-amber-800 dark:text-amber-300">{certificateWarning}</p>
          )}
          <p className="text-xs text-muted">
            Monitor mode never requests a certificate from your CA. Choose one already in this
            server's machine store, an autoenrolled one for example, or keep the self signed
            certificate the service generates, which browsers will warn about. When an
            autoenrolled certificate renews, the service follows it at its next restart.
          </p>
        </div>

        {loading && (
          <div className="flex items-center gap-2 text-sm text-muted">
            <Loader2 className="h-4 w-4 animate-spin" />
            Reading the machine store...
          </div>
        )}

        {loadError && (
          <p className="text-xs text-red-700 dark:text-red-300">{loadError}</p>
        )}

        {!loading && certificates && (
          <div className="space-y-2" role="radiogroup" aria-label="HTTPS certificate">
            <label
              className={`flex items-start gap-3 p-3 rounded-lg border cursor-pointer ${
                keepingSelfSigned
                  ? 'border-certus-300 bg-certus-50 dark:bg-certus-500/10'
                  : 'border-hairline bg-surface hover:border-hairline-strong'
              }`}
            >
              <input
                type="radio"
                name="https-certificate"
                checked={keepingSelfSigned}
                onChange={() => choose(SELF_SIGNED)}
                className="mt-1"
              />
              <span className="text-sm text-ink">
                Keep the self signed certificate
                <span className="block text-xs text-muted">
                  Browsers warn until each one trusts it. Fine for a first look.
                </span>
              </span>
            </label>

            {certificates.map((certificate) => (
              <CertificateRow
                key={certificate.thumbprint}
                certificate={certificate}
                externalHost={externalHost}
                selected={choice === certificate.thumbprint}
                onSelect={() => choose(certificate.thumbprint)}
              />
            ))}

            {certificates.length === 0 && (
              <p className="text-xs text-muted">
                No certificate in this server's machine store (LocalMachine\My) can serve HTTPS:
                one needs its private key, a current validity, and server authentication. Enrol or
                import one there, then look again.
              </p>
            )}
          </div>
        )}

        {mismatchNames && (
          <div className="rounded-lg border border-amber-300 bg-amber-100 dark:bg-amber-500/15 p-3 space-y-2">
            <p className="text-xs text-amber-900 dark:text-amber-200">
              This certificate is for{' '}
              <code className="font-mono">{mismatchNames.join(', ') || '(no names)'}</code>, not{' '}
              <code className="font-mono">{externalHost}</code>. Browsers opening the dashboard at the
              server URL would reject it.
            </p>
            <button
              onClick={() => handleUse(true)}
              disabled={busy}
              className="inline-flex items-center gap-2 px-3 py-1.5 text-xs font-semibold
                         text-amber-900 dark:text-amber-200 bg-surface border border-amber-300 rounded-lg
                         hover:bg-amber-50 disabled:opacity-50 transition-colors"
            >
              Use it anyway
            </button>
          </div>
        )}

        <div className="flex flex-wrap items-center gap-2">
          {keepingSelfSigned ? (
            configured !== null && (
              <button
                onClick={handleKeepSelfSigned}
                disabled={busy}
                className="inline-flex items-center gap-2 px-3 py-1.5 text-xs font-semibold
                           text-white bg-certus-600 rounded-lg hover:bg-certus-700
                           disabled:opacity-50 transition-colors"
              >
                {busy && <Loader2 className="h-3.5 w-3.5 animate-spin" />}
                Go back to the self signed certificate
              </button>
            )
          ) : (
            !unchanged && (
              <button
                onClick={() => handleUse(false)}
                disabled={busy || mismatchNames !== null}
                className="inline-flex items-center gap-2 px-3 py-1.5 text-xs font-semibold
                           text-white bg-certus-600 rounded-lg hover:bg-certus-700
                           disabled:opacity-50 transition-colors"
              >
                {busy ? <Loader2 className="h-3.5 w-3.5 animate-spin" /> : <ShieldCheck className="h-3.5 w-3.5" />}
                Use this certificate
              </button>
            )
          )}
          <button
            onClick={() => setReloads((n) => n + 1)}
            disabled={busy || loading}
            className="inline-flex items-center gap-2 px-3 py-1.5 text-xs font-semibold
                       text-ink-soft bg-surface border border-hairline-strong rounded-lg
                       hover:bg-sunken disabled:opacity-50 transition-colors"
          >
            <RefreshCw className="h-3.5 w-3.5" />
            Look again
          </button>
        </div>

        {message && (
          <p className="text-xs text-red-700 dark:text-red-300 whitespace-pre-line">{message}</p>
        )}
      </div>
    </div>
  );
}

function CertificateRow({
  certificate,
  externalHost,
  selected,
  onSelect,
}: {
  certificate: ExistingCertificate;
  externalHost: string;
  selected: boolean;
  onSelect: () => void;
}) {
  const expires = new Date(certificate.notAfter).toLocaleDateString();
  return (
    <label
      className={`flex items-start gap-3 p-3 rounded-lg border cursor-pointer ${
        selected
          ? 'border-certus-300 bg-certus-50 dark:bg-certus-500/10'
          : 'border-hairline bg-surface hover:border-hairline-strong'
      }`}
    >
      <input
        type="radio"
        name="https-certificate"
        checked={selected}
        onChange={onSelect}
        className="mt-1"
      />
      <span className="min-w-0 space-y-1">
        <span className="block text-sm text-ink break-all">
          {certificate.names.join(', ') || certificate.subject}
        </span>
        <span className="block text-xs text-muted break-all">
          Issued by {certificate.issuer}, expires {expires}
          {certificate.template ? `, template ${certificate.template}` : ''}
        </span>
        <span className="flex flex-wrap gap-1.5">
          {certificate.coversExternalHost ? (
            <Badge tone="good">Covers {externalHost}</Badge>
          ) : (
            <Badge tone="warn">Does not cover {externalHost}</Badge>
          )}
          {certificate.selfSigned && <Badge tone="warn">Self signed</Badge>}
          {certificate.configured && <Badge tone="info">In use</Badge>}
        </span>
        <span className="block text-[11px] font-mono text-faint break-all">{certificate.thumbprint}</span>
      </span>
    </label>
  );
}

function Badge({ tone, children }: { tone: 'good' | 'warn' | 'info'; children: React.ReactNode }) {
  const colours = {
    good: 'bg-emerald-50 dark:bg-emerald-500/10 text-emerald-700 dark:text-emerald-300 border-emerald-200 dark:border-emerald-500/30',
    warn: 'bg-amber-50 dark:bg-amber-500/10 text-amber-800 dark:text-amber-300 border-amber-200 dark:border-amber-500/30',
    info: 'bg-certus-50 dark:bg-certus-500/10 text-certus-700 dark:text-certus-300 border-certus-200 dark:border-certus-500/30',
  }[tone];
  return (
    <span className={`inline-flex items-center px-2 py-0.5 rounded-md text-[11px] font-medium border ${colours}`}>
      {children}
    </span>
  );
}
