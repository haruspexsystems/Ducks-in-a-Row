import { useMemo, useState } from 'react';
import { useQuery } from '@tanstack/react-query';
import { AlertTriangle, Download } from 'lucide-react';
import { fetchSetupConfig } from '@/api/setup';
import { CopyButton } from '@/components/CopyButton';
import {
  SECRET_PLACEHOLDER,
  buildDirectoryUrl,
  buildEabSnippets,
} from './eabSnippets';

/**
 * Ready to paste client setup for one EAB credential: a template picker
 * (each template is its own ACME directory), a client picker, and the
 * snippet with copy and download. Rendered in two places: inside the show
 * once secret panel with the real secret inlined, and from the per row
 * "Client setup" expander, where the secret is a paste placeholder because
 * the server never returns a stored secret again.
 */
export function EabClientSnippets({
  keyId,
  secret,
}: {
  keyId: string;
  /** The plaintext secret while it is on screen; null once it is gone. */
  secret: string | null;
}) {
  // Shares the layout's cache entry; one fetch serves the whole app, and
  // like the layout's observer it does not refetch on window focus (the
  // config only changes across a restart).
  const { data: config, isError } = useQuery({
    queryKey: ['setup-config'],
    queryFn: fetchSetupConfig,
    staleTime: 5 * 60_000,
    retry: false,
    refetchOnWindowFocus: false,
  });

  const templates = config?.enabledTemplates ?? [];
  const [templateChoice, setTemplateChoice] = useState<string | null>(null);
  const template = templateChoice ?? templates[0] ?? 'WebServer';

  // Without a saved external URL the browser's own origin is the best
  // available guess; the hint below says why it may be wrong for clients.
  // The hint also covers a failed config fetch, because then the fallback
  // is in use and the snippet should not look authoritative. It stays
  // hidden only while the config is genuinely still loading.
  const savedUrl = config?.externalUrl?.trim();
  const externalUrl = savedUrl || window.location.origin;
  const missingExternalUrl = !savedUrl && (isError || config !== undefined);

  const snippets = useMemo(
    () =>
      buildEabSnippets(
        buildDirectoryUrl(externalUrl, template),
        keyId,
        secret ?? SECRET_PLACEHOLDER,
      ),
    [externalUrl, template, keyId, secret],
  );
  const [clientChoice, setClientChoice] = useState(snippets[0].id);
  const snippet = snippets.find((s) => s.id === clientChoice) ?? snippets[0];

  return (
    <div className="space-y-3">
      <div className="flex flex-wrap items-center gap-2">
        <span className="text-xs font-medium text-ink-mid">Client setup</span>
        {templates.length > 1 && (
          <select
            value={template}
            onChange={(e) => setTemplateChoice(e.target.value)}
            className="px-2 py-1 bg-surface border border-hairline-strong rounded text-xs text-ink-soft
                       focus:outline-none focus:ring-2 focus:ring-certus-500 focus:border-certus-500"
            aria-label="Certificate template"
          >
            {templates.map((t) => (
              <option key={t} value={t}>
                {t}
              </option>
            ))}
          </select>
        )}
        <div className="flex flex-wrap gap-1">
          {snippets.map((s) => (
            <button
              key={s.id}
              onClick={() => setClientChoice(s.id)}
              className={`px-2 py-1 rounded text-xs font-medium transition-colors ${
                s.id === snippet.id
                  ? 'bg-certus-600 text-white'
                  : 'bg-surface border border-hairline-strong text-ink-mid hover:bg-sunken-strong'
              }`}
            >
              {s.client}
            </button>
          ))}
        </div>
      </div>

      {missingExternalUrl && (
        <div className="bg-amber-50 dark:bg-amber-500/10 border border-amber-200 dark:border-amber-500/30 rounded-lg p-2 flex items-start gap-2">
          <AlertTriangle className="h-3.5 w-3.5 text-amber-600 mt-0.5" />
          <p className="text-xs text-amber-800 dark:text-amber-300">
            No external URL is saved, so the snippet uses this browser's
            address. Set the external URL on the Settings page to the name
            your clients reach the server by.
          </p>
        </div>
      )}

      <div className="relative">
        <pre
          className="bg-surface border border-hairline rounded-lg p-3 pr-16 text-xs font-mono
                     text-ink-strong whitespace-pre overflow-x-auto"
        >
          {snippet.text}
        </pre>
        <div className="absolute top-2 right-2 flex items-center gap-1 bg-surface/90 rounded px-1">
          <CopyButton value={snippet.text} label={`${snippet.client} setup`} />
          <button
            onClick={() => downloadText(snippet.filename, snippet.text)}
            className="text-faint hover:text-ink-mid transition-colors"
            title={`Download ${snippet.filename}`}
            aria-label={`Download ${snippet.filename}`}
          >
            <Download className="h-3.5 w-3.5" />
          </button>
        </div>
      </div>

      {secret === null && (
        <p className="text-xs text-muted">
          The server stores the secret encrypted and cannot show it again:
          paste the copy you saved over{' '}
          <code className="font-mono">{SECRET_PLACEHOLDER}</code>. If it is
          lost, regenerate the secret and use the new value.
        </p>
      )}
    </div>
  );
}

/**
 * Hand the snippet to the browser as a small text file download. The
 * anchor is attached to the document and the blob URL revoked on a delay,
 * because Firefox may ignore a click on a detached anchor and can abort a
 * download whose URL is revoked in the same task.
 */
function downloadText(filename: string, text: string) {
  const url = URL.createObjectURL(new Blob([text], { type: 'text/plain' }));
  const anchor = document.createElement('a');
  anchor.href = url;
  anchor.download = filename;
  document.body.appendChild(anchor);
  anchor.click();
  anchor.remove();
  setTimeout(() => URL.revokeObjectURL(url), 10_000);
}
