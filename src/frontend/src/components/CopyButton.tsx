import { Copy, CheckCircle2 } from 'lucide-react';
import { useEffect, useRef, useState } from 'react';

/**
 * Small copy-to-clipboard button with the two second "copied" check mark,
 * extracted from the certificate detail page idiom.
 *
 * The value may be a string or a function returning one, for content the page
 * does not hold until the button is pressed. The certificate PEM is the case
 * that needs it: fetching it on every detail page load would cost a request per
 * view for a button most readers never press.
 *
 * The two failure modes are deliberately not treated alike. A clipboard that is
 * unavailable or denied fails quietly, exactly as it always has: that is the
 * reader's browser context, nothing they asked for went wrong, and a
 * non secure context would otherwise complain on every press. A value that
 * could not be fetched is a different thing, so it calls onError and the caller
 * says so. Without that, a press that silently does nothing reads as a broken
 * button.
 */
export function CopyButton({
  value,
  label,
  onError,
}: {
  value: string | (() => Promise<string>);
  label: string;
  onError?: (message: string) => void;
}) {
  const [copied, setCopied] = useState(false);
  const [busy, setBusy] = useState(false);
  const copyTimer = useRef<ReturnType<typeof setTimeout>>();
  // Set on unmount so the async path below does not call setState afterwards,
  // which the fetching value case makes reachable: the reader can navigate away
  // while the request is still open.
  const unmounted = useRef(false);

  useEffect(() => () => {
    unmounted.current = true;
    if (copyTimer.current) clearTimeout(copyTimer.current);
  }, []);

  const handleCopy = async () => {
    if (busy) return;

    let text: string;
    if (typeof value === 'string') {
      text = value;
    } else {
      setBusy(true);
      try {
        text = await value();
      } catch {
        if (!unmounted.current) onError?.('Could not fetch the certificate.');
        return;
      } finally {
        if (!unmounted.current) setBusy(false);
      }
    }

    try {
      if (!navigator.clipboard) throw new Error('Clipboard unavailable');
      await navigator.clipboard.writeText(text);
      if (unmounted.current) return;
      setCopied(true);
      if (copyTimer.current) clearTimeout(copyTimer.current);
      copyTimer.current = setTimeout(() => setCopied(false), 2000);
    } catch {
      // Clipboard API is unavailable (non-secure context) or was denied; fail quietly.
    }
  };

  return (
    <button
      onClick={handleCopy}
      disabled={busy}
      className="inline-flex items-center text-faint hover:text-ink-mid disabled:opacity-50"
      title="Copy to clipboard"
      aria-label={`Copy ${label}`}
    >
      {copied ? (
        <CheckCircle2 className="h-3.5 w-3.5 text-emerald-500" />
      ) : (
        <Copy className="h-3.5 w-3.5" />
      )}
    </button>
  );
}
