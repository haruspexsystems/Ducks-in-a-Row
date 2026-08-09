import { useEffect, useRef, useState } from 'react';
import { AlertTriangle } from 'lucide-react';
import type { CertificateDetail } from '@/types';
import { REVOCATION_REASON_OPTIONS, certificateDisplayName } from '@/types';
import { ApiError, revokeCertificate } from '@/api/client';
import type { RevokeCertificateResult } from '@/api/client';

/** RFC 5280 code for Certificate Hold, the one reversible reason. */
const CERTIFICATE_HOLD = 6;

/**
 * The typed confirmation dialog for revoking one certificate (issue #159).
 * This action reaches the CA and can revoke any certificate in the estate,
 * Ducks issued or not, so the dialog is deliberately heavier than a yes or
 * no: it shows the full identity of the target (subject, SANs, template,
 * serial), warns distinctly when the certificate did not come through Ducks,
 * requires a reason with no preselected default, and requires typing the
 * certificate's display name before the button arms.
 */
export function RevokeCertificateDialog({
  cert,
  onClose,
  onRevoked,
}: {
  cert: CertificateDetail;
  onClose: () => void;
  onRevoked: (result: RevokeCertificateResult) => void;
}) {
  const [reason, setReason] = useState('');
  const [typedName, setTypedName] = useState('');
  const [busy, setBusy] = useState(false);
  const [error, setError] = useState<string | null>(null);

  const panelRef = useRef<HTMLDivElement>(null);
  const reasonRef = useRef<HTMLSelectElement>(null);

  useEffect(() => {
    reasonRef.current?.focus();
  }, []);

  // The display name is what the admin must type back. The fallback chain
  // bottoms out at "Request {id}", so there is always something typable.
  const displayName = certificateDisplayName(cert);
  const nameMatches = typedName.trim() === displayName;
  const armed = reason !== '' && nameMatches && !busy;

  const close = () => {
    if (!busy) onClose();
  };

  const handleKeyDown = (event: React.KeyboardEvent) => {
    if (event.key === 'Escape') {
      event.stopPropagation();
      close();
      return;
    }
    // Keep Tab inside the dialog. A revocation dialog must not let focus
    // wander into the page underneath it.
    if (event.key === 'Tab' && panelRef.current) {
      const focusable = panelRef.current.querySelectorAll<HTMLElement>(
        'button, input, select, [tabindex]:not([tabindex="-1"])'
      );
      if (focusable.length === 0) return;
      const first = focusable[0];
      const last = focusable[focusable.length - 1];
      if (event.shiftKey && document.activeElement === first) {
        event.preventDefault();
        last.focus();
      } else if (!event.shiftKey && document.activeElement === last) {
        event.preventDefault();
        first.focus();
      }
    }
  };

  const handleRevoke = async () => {
    if (!armed || !cert.serialNumber) return;
    setBusy(true);
    setError(null);
    try {
      const result = await revokeCertificate(cert.id, Number(reason), cert.serialNumber);
      onRevoked(result);
    } catch (e) {
      setBusy(false);
      setError(messageFor(e));
    }
  };

  // A row without a serial cannot be revoked; the page never opens the
  // dialog for one, and this guard keeps the type checker honest.
  if (!cert.serialNumber) return null;

  return (
    <div
      className="fixed inset-0 z-50 flex items-center justify-center bg-slate-900/50 p-4"
      onMouseDown={close}
      onKeyDown={handleKeyDown}
    >
      <div
        ref={panelRef}
        role="dialog"
        aria-modal="true"
        aria-labelledby="revoke-dialog-title"
        className="w-full max-w-lg max-h-[90vh] overflow-y-auto bg-surface rounded-lg shadow-xl border border-hairline"
        onMouseDown={(event) => event.stopPropagation()}
      >
        <div className="px-5 py-4 border-b border-hairline-soft">
          <h2 id="revoke-dialog-title" className="text-lg font-semibold text-ink">
            Revoke {displayName}
          </h2>
        </div>

        <div className="px-5 py-4 space-y-4">
          {/* The target, unambiguously. The admin confirms against these
              facts, and the serial shown here is what the request binds to. */}
          <dl className="text-sm border border-hairline rounded-lg divide-y divide-hairline-soft">
            <FactRow label="Subject" value={cert.subject || '—'} />
            {cert.subjectAlternativeNames && (
              <FactRow label="SANs" value={cert.subjectAlternativeNames} />
            )}
            <FactRow label="Template" value={cert.templateName} />
            <FactRow label="Serial" value={cert.serialNumber} mono />
          </dl>

          {!cert.issuedByAcme && (
            <div className="border rounded-lg p-3 bg-amber-50 dark:bg-amber-500/10 border-amber-300 flex gap-2">
              <AlertTriangle className="h-4 w-4 text-amber-600 shrink-0 mt-0.5" />
              <p className="text-sm text-amber-900 dark:text-amber-200">
                <span className="font-semibold">Not issued through Ducks.</span> This
                certificate reached the inventory from the CA database and may belong to
                another system, such as a domain controller or an auto enrolled machine.
                Revoking it can break that system.
              </p>
            </div>
          )}

          <div className="border rounded-lg p-3 bg-red-50 dark:bg-red-500/10 border-red-200 dark:border-red-500/30">
            <p className="text-sm text-red-900 dark:text-red-200">
              Revocation is permanent. Certificate Hold is the only reason that can be
              undone. Anything using this certificate will stop being trusted once the
              CA publishes its next revocation list.
            </p>
          </div>

          <div>
            <label htmlFor="revoke-reason" className="block text-sm font-medium text-ink-soft">
              Reason
            </label>
            <select
              id="revoke-reason"
              ref={reasonRef}
              value={reason}
              onChange={(event) => setReason(event.target.value)}
              disabled={busy}
              className="mt-1 block w-full rounded-md border border-hairline-strong bg-surface px-3 py-2 text-sm text-ink focus:border-certus-500 focus:outline-none"
            >
              <option value="" disabled>
                Select a reason
              </option>
              {REVOCATION_REASON_OPTIONS.map((option) => (
                <option key={option.code} value={option.code}>
                  {option.label}
                </option>
              ))}
            </select>
            {Number(reason) === CERTIFICATE_HOLD && reason !== '' && (
              <p className="mt-1 text-xs text-muted">
                Certificate Hold is the only reversible reason; the hold is released from
                the Certification Authority console.
              </p>
            )}
          </div>

          <div>
            <label htmlFor="revoke-confirm" className="block text-sm font-medium text-ink-soft">
              Type <span className="font-semibold">{displayName}</span> to confirm
            </label>
            <input
              id="revoke-confirm"
              type="text"
              value={typedName}
              onChange={(event) => setTypedName(event.target.value)}
              disabled={busy}
              autoComplete="off"
              spellCheck={false}
              className="mt-1 block w-full rounded-md border border-hairline-strong px-3 py-2 text-sm text-ink focus:border-certus-500 focus:outline-none"
            />
          </div>

          {error && (
            <p className="text-sm text-red-600" role="alert">
              {error}
            </p>
          )}
        </div>

        <div className="px-5 py-4 border-t border-hairline-soft flex justify-end gap-2">
          <button
            onClick={close}
            disabled={busy}
            className="rounded-md border border-hairline-strong px-4 py-2 text-sm font-medium text-ink-soft hover:bg-sunken disabled:opacity-50"
          >
            Cancel
          </button>
          <button
            onClick={handleRevoke}
            disabled={!armed}
            className="rounded-md bg-red-600 px-4 py-2 text-sm font-medium text-white hover:bg-red-700 disabled:bg-red-300"
          >
            {busy ? 'Revoking…' : 'Revoke certificate'}
          </button>
        </div>
      </div>
    </div>
  );
}

/**
 * Error wording keyed on the problem type. The already revoked case gets its
 * own sentence because it is the one refusal whose remedy is just a refresh.
 */
function messageFor(e: unknown): string {
  if (e instanceof ApiError) {
    if (e.problemType?.endsWith('/certificate-already-revoked')) {
      return 'The certification authority already lists this certificate as revoked. Reload the page to see its current state.';
    }
    return e.problemDetail ?? e.problemTitle ?? 'The revocation request failed.';
  }
  return 'The revocation request failed. Check the network and try again.';
}

function FactRow({ label, value, mono }: { label: string; value: string; mono?: boolean }) {
  return (
    <div className="flex items-start justify-between gap-4 px-3 py-2">
      <dt className="text-muted whitespace-nowrap">{label}</dt>
      <dd className={`text-ink text-right break-all ${mono ? 'font-mono text-xs' : ''}`}>
        {value}
      </dd>
    </div>
  );
}
