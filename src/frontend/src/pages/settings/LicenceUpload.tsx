import { useRef, useState, type DragEvent } from 'react';
import { AlertTriangle, CheckCircle2, FileUp, Loader2 } from 'lucide-react';
import { errorText } from '@/api/client';
import {
  inspectLicence,
  installLicence,
  type LicenceDowngrade,
  type LicenceInspectResponse,
  type LicenceStatusResponse,
} from '@/api/licence';
import { describeCandidate, MAX_LICENCE_BYTES, type CandidateVerdict } from '@/lib/licence';
import { LicenceFacts } from './LicenceFacts';

type Phase = 'choose' | 'checking' | 'preview' | 'installing' | 'downgrade';

const LICENCE_MEDIA_TYPE = 'application/jose+json';

/**
 * Choosing, previewing and activating a licence file (licence design section
 * 13.4, issue #493). The file is read once and the same bytes go to the preview
 * and to the install, so what was previewed is what gets installed. Pasted text
 * is sent exactly as typed, never trimmed.
 */
export function LicenceUpload({
  installed,
  onInstalled,
  onCancel,
}: {
  installed: LicenceStatusResponse;
  onInstalled: (status: LicenceStatusResponse) => void;
  onCancel: () => void;
}) {
  const [phase, setPhase] = useState<Phase>('choose');
  const [source, setSource] = useState<{ blob: Blob; name: string } | null>(null);
  const [pasted, setPasted] = useState('');
  const [inspected, setInspected] = useState<LicenceInspectResponse | null>(null);
  const [verdict, setVerdict] = useState<CandidateVerdict | null>(null);
  const [downgrade, setDowngrade] = useState<LicenceDowngrade | null>(null);
  const [error, setError] = useState<string | null>(null);
  const [dragging, setDragging] = useState(false);
  const fileInput = useRef<HTMLInputElement>(null);

  const startOver = () => {
    setPhase('choose');
    setSource(null);
    setInspected(null);
    setVerdict(null);
    setDowngrade(null);
    setError(null);
  };

  const preview = async (blob: Blob, name: string) => {
    setError(null);
    if (blob.size === 0) {
      setError('The file is empty.');
      return;
    }
    if (blob.size > MAX_LICENCE_BYTES) {
      setError(`A licence file is at most ${MAX_LICENCE_BYTES.toLocaleString()} bytes, and this one is ${blob.size.toLocaleString()}.`);
      return;
    }
    setSource({ blob, name });
    setPhase('checking');
    try {
      const result = await inspectLicence(blob);
      setInspected(result);
      setVerdict(describeCandidate(result));
      setPhase('preview');
    } catch (err) {
      setError(errorText(err, 'The file could not be checked.'));
      setPhase('choose');
    }
  };

  const chooseFile = async (file: File | undefined) => {
    if (!file) return;
    // Read once into memory, so the preview and the install send the same bytes
    // even if the file changes on disk in between.
    let bytes: ArrayBuffer;
    try {
      bytes = await file.arrayBuffer();
    } catch {
      setError(`${file.name} could not be read. Choose it again, or paste its text.`);
      return;
    }
    await preview(new Blob([bytes], { type: LICENCE_MEDIA_TYPE }), file.name);
  };

  const previewPasted = async () => {
    if (pasted.length === 0) {
      setError('Paste the licence text first.');
      return;
    }
    await preview(new Blob([pasted], { type: LICENCE_MEDIA_TYPE }), 'Pasted text');
  };

  const install = async (confirm: boolean) => {
    if (!source) return;
    setError(null);
    setPhase('installing');
    try {
      const outcome = await installLicence(source.blob, confirm);
      if (outcome.kind === 'wouldDowngrade') {
        setDowngrade(outcome.refusal);
        setPhase('downgrade');
        return;
      }
      onInstalled(outcome.status);
    } catch (err) {
      setError(errorText(err, 'The licence could not be installed.'));
      setPhase(confirm ? 'downgrade' : 'preview');
    }
  };

  const onDrop = (event: DragEvent<HTMLDivElement>) => {
    event.preventDefault();
    setDragging(false);
    void chooseFile(event.dataTransfer.files[0]);
  };

  const busy = phase === 'checking' || phase === 'installing';

  return (
    <div className="border border-hairline rounded-lg p-4 space-y-3">
      {phase === 'choose' && (
        <>
          <div
            onDragOver={(event) => {
              event.preventDefault();
              setDragging(true);
            }}
            onDragLeave={() => setDragging(false)}
            onDrop={onDrop}
            className={`rounded-lg border-2 border-dashed p-4 text-center text-xs text-muted transition-colors ${
              dragging ? 'border-certus-500 bg-certus-50 dark:bg-certus-500/10' : 'border-hairline-strong'
            }`}
          >
            <FileUp className="h-5 w-5 mx-auto mb-1 text-faint" />
            Drop the licence file here, or{' '}
            <button
              type="button"
              onClick={() => fileInput.current?.click()}
              className="font-semibold text-certus-600 hover:text-certus-800 dark:text-certus-300"
            >
              choose a file
            </button>
            .
            <input
              ref={fileInput}
              type="file"
              className="hidden"
              aria-label="Licence file"
              onChange={(event) => {
                void chooseFile(event.target.files?.[0]);
                event.target.value = '';
              }}
            />
          </div>

          <div className="space-y-1.5">
            <label htmlFor="licence-paste" className="block text-xs font-medium text-ink-soft">
              Or paste the licence text
            </label>
            <textarea
              id="licence-paste"
              rows={4}
              value={pasted}
              onChange={(event) => setPasted(event.target.value)}
              spellCheck={false}
              className="w-full px-3 py-2 text-xs font-mono bg-surface text-ink border border-hairline-strong rounded-lg
                         focus:outline-none focus:ring-2 focus:ring-certus-500"
            />
            <p className="text-xs text-muted">
              The text is used exactly as pasted. Mail programs can wrap long lines, which breaks the
              file; if the check refuses it, choose the file itself instead.
            </p>
          </div>

          <div className="flex gap-2">
            <button
              type="button"
              onClick={() => void previewPasted()}
              disabled={pasted.length === 0}
              className="px-3 py-1.5 text-xs font-semibold text-white bg-certus-600 rounded-lg hover:bg-certus-700 disabled:opacity-50"
            >
              Check the pasted text
            </button>
            <CancelButton onClick={onCancel} />
          </div>
        </>
      )}

      {busy && (
        <div className="flex items-center gap-2 text-xs text-faint py-1">
          <Loader2 className="h-4 w-4 animate-spin" />
          {phase === 'checking' ? 'Asking the paid module to check the file' : 'Installing the licence'}
        </div>
      )}

      {phase === 'preview' && verdict && inspected && (
        <>
          <p className="text-xs text-faint">Checked: {source?.name}</p>
          <VerdictCallout verdict={verdict} />
          {verdict.kind === 'verified' && inspected.candidate && (
            <LicenceFacts licence={inspected.candidate.licence} />
          )}
          {verdict.kind === 'verified' && verdict.notes.map((note) => (
            <p key={note} className="text-xs text-amber-800 dark:text-amber-300">{note}</p>
          ))}
          {verdict.kind === 'verified' && verdict.worse && (
            <p className="text-xs text-amber-800 dark:text-amber-300">
              The paid module judges this licence worse than the one installed now. Activating it asks
              you to confirm first.
            </p>
          )}
          <div className="flex flex-wrap gap-2">
            {verdict.kind === 'verified' && (
              <PrimaryButton onClick={() => void install(false)}>Activate</PrimaryButton>
            )}
            {verdict.kind === 'noModule' && (
              <PrimaryButton onClick={() => void install(false)}>Store it</PrimaryButton>
            )}
            <SecondaryButton onClick={startOver}>Choose another file</SecondaryButton>
            <CancelButton onClick={onCancel} />
          </div>
        </>
      )}

      {phase === 'downgrade' && downgrade && (
        <div className="bg-amber-50 dark:bg-amber-500/10 border border-amber-200 dark:border-amber-500/30 rounded-lg p-3 space-y-3">
          <p className="text-xs font-semibold text-amber-900 dark:text-amber-200">
            This licence is worse than the one installed now
          </p>
          <p className="text-xs text-amber-800 dark:text-amber-300">
            The paid module compared the two. Read both before you go on; the one installed now is
            kept as the previous licence, so Restore previous licence can undo this.
          </p>
          <div className="grid grid-cols-1 sm:grid-cols-2 gap-4">
            <LicenceFacts licence={installed.licence} title="Installed now" />
            <LicenceFacts licence={downgrade.candidate.licence} title="This file" />
          </div>
          <div className="flex gap-2">
            <button
              type="button"
              onClick={() => void install(true)}
              className="px-3 py-1.5 text-xs font-semibold text-white bg-amber-600 rounded-lg hover:bg-amber-700"
            >
              Install anyway
            </button>
            <CancelButton onClick={onCancel} />
          </div>
        </div>
      )}

      {error && (
        <div className="bg-red-50 dark:bg-red-500/10 border border-red-200 dark:border-red-500/30 rounded-lg p-3 flex items-start gap-2">
          <AlertTriangle className="h-4 w-4 text-red-500 mt-0.5 shrink-0" />
          <p className="text-xs text-red-700 dark:text-red-300">{error}</p>
        </div>
      )}
    </div>
  );
}

function VerdictCallout({ verdict }: { verdict: CandidateVerdict }) {
  const good = verdict.kind === 'verified' && !verdict.worse;
  const bad = verdict.kind === 'invalid';
  const classes = good
    ? 'bg-emerald-50 dark:bg-emerald-500/10 border-emerald-200 dark:border-emerald-500/30 text-emerald-800 dark:text-emerald-300'
    : bad
      ? 'bg-red-50 dark:bg-red-500/10 border-red-200 dark:border-red-500/30 text-red-700 dark:text-red-300'
      : 'bg-amber-50 dark:bg-amber-500/10 border-amber-200 dark:border-amber-500/30 text-amber-800 dark:text-amber-300';
  const Icon = good ? CheckCircle2 : AlertTriangle;
  return (
    <div className={`border rounded-lg p-3 flex items-start gap-2 ${classes}`}>
      <Icon className="h-4 w-4 mt-0.5 shrink-0" />
      <p className="text-xs">{verdict.summary}</p>
    </div>
  );
}

function PrimaryButton({ onClick, children }: { onClick: () => void; children: React.ReactNode }) {
  return (
    <button
      type="button"
      onClick={onClick}
      className="px-3 py-1.5 text-xs font-semibold text-white bg-certus-600 rounded-lg hover:bg-certus-700"
    >
      {children}
    </button>
  );
}

function SecondaryButton({ onClick, children }: { onClick: () => void; children: React.ReactNode }) {
  return (
    <button
      type="button"
      onClick={onClick}
      className="px-3 py-1.5 text-xs font-medium text-ink-soft border border-hairline-strong rounded-lg hover:bg-sunken"
    >
      {children}
    </button>
  );
}

function CancelButton({ onClick }: { onClick: () => void }) {
  return (
    <button
      type="button"
      onClick={onClick}
      className="px-3 py-1.5 text-xs font-medium text-muted hover:text-ink"
    >
      Cancel
    </button>
  );
}
