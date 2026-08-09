import { useEffect, useState } from 'react';
import { Cog, Loader2, Monitor, User, Users, X } from 'lucide-react';
import {
  searchDirectoryPrincipals,
  type AdPrincipal,
  type EabCredentialPrincipal,
} from '@/api/acme';

/**
 * Debounced type ahead over the directory principals endpoint, for picking
 * a credential's owner. Inline by design: the results render as a plain
 * list under the input, no modal. With a selection made, the picker shows
 * it as a chip with a remove button; clearing returns to the input. The
 * search is best effort server side, so an unreachable directory looks
 * like "no matches" and the empty state says so.
 */
export function PrincipalPicker({
  value,
  onChange,
}: {
  value: EabCredentialPrincipal | null;
  onChange: (principal: EabCredentialPrincipal | null) => void;
}) {
  const [query, setQuery] = useState('');
  const [results, setResults] = useState<AdPrincipal[] | null>(null);
  const [searching, setSearching] = useState(false);
  const [searchFailed, setSearchFailed] = useState(false);

  useEffect(() => {
    const trimmed = query.trim();
    if (trimmed.length === 0) {
      setResults(null);
      setSearching(false);
      setSearchFailed(false);
      return;
    }
    // The cleanup marks this run stale and aborts its in flight request, so
    // a superseded keystroke can neither write state out of order nor keep
    // the server searching the directory for an answer nobody wants.
    let stale = false;
    const abort = new AbortController();
    setSearching(true);
    const timer = setTimeout(async () => {
      try {
        const found = await searchDirectoryPrincipals(trimmed, abort.signal);
        if (stale) return;
        setResults(found);
        setSearchFailed(false);
        setSearching(false);
      } catch {
        if (stale) return;
        setResults([]);
        setSearchFailed(true);
        setSearching(false);
      }
    }, 300);
    return () => {
      stale = true;
      clearTimeout(timer);
      abort.abort();
    };
  }, [query]);

  if (value) {
    return (
      <span className="inline-flex items-center gap-2 px-2.5 py-1.5 bg-sunken-strong rounded-lg">
        <TypeIcon type={value.type} />
        <span className="text-sm text-ink-strong">{value.name}</span>
        <span className="text-xs text-muted">({value.type})</span>
        <button
          onClick={() => onChange(null)}
          className="text-faint hover:text-ink-mid"
          aria-label="Remove the owner"
          title="Remove the owner"
        >
          <X className="h-3.5 w-3.5" />
        </button>
      </span>
    );
  }

  return (
    <div className="space-y-2">
      <div className="relative">
        <input
          type="text"
          value={query}
          onChange={(e) => setQuery(e.target.value)}
          placeholder="Search users, computers, and groups"
          className="w-full px-3 py-2 bg-surface border border-hairline-strong rounded-lg text-sm
                     placeholder:text-faint focus:outline-none focus:ring-2
                     focus:ring-certus-500 focus:border-certus-500"
        />
        {searching && (
          <Loader2 className="h-4 w-4 animate-spin text-faint absolute right-3 top-2.5" />
        )}
      </div>
      {results !== null && results.length > 0 && (
        <ul className="border border-hairline rounded-lg divide-y divide-hairline-soft max-h-48
                       overflow-y-auto bg-surface">
          {results.map((principal) => (
            <li key={principal.sid}>
              <button
                type="button"
                onClick={() => {
                  onChange({
                    sid: principal.sid,
                    name: principal.name,
                    type: principal.type,
                  });
                  setQuery('');
                }}
                className="w-full flex items-center gap-2 px-3 py-2 text-left hover:bg-sunken
                           transition-colors"
                title={principal.distinguishedName ?? principal.sid}
              >
                <TypeIcon type={principal.type} />
                <span className="text-sm text-ink-strong">{principal.name}</span>
                <span className="text-xs text-faint">{principal.type}</span>
              </button>
            </li>
          ))}
        </ul>
      )}
      {results !== null && results.length === 0 && !searching && (
        <p className="text-xs text-muted">
          {searchFailed
            ? 'The directory search failed. Try again.'
            : 'No matching principals. A server that cannot reach the directory also answers with no results.'}
        </p>
      )}
    </div>
  );
}

/** The small type marker shown next to a principal name. */
function TypeIcon({ type }: { type: string }) {
  const Icon =
    type === 'computer' ? Monitor
    : type === 'group' ? Users
    : type === 'service account' ? Cog
    : User;
  return <Icon className="h-3.5 w-3.5 text-muted shrink-0" />;
}
