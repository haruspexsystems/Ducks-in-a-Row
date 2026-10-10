import { useState } from 'react';
import { Plus, X } from 'lucide-react';

interface DomainListEditorProps {
  domains: string[];
  onAdd: (domain: string) => void;
  onRemove: (domain: string) => void;
  disabled?: boolean;
  /** Extra control rendered next to the input, e.g. "Add my AD domain". */
  extraAction?: React.ReactNode;
  /** Copy for the empty list state; the default suits the global allowed list. */
  emptyText?: string;
}

/**
 * A small add and remove editor for the allowed domain list, shared by the
 * settings card and the setup wizard step. Dumb on purpose: the parents own
 * the list state, and entries are validated server side on save, where the
 * normalization rules live.
 */
export function DomainListEditor({
  domains,
  onAdd,
  onRemove,
  disabled = false,
  extraAction,
  emptyText = 'No domains yet. Add the domains this server may issue certificates for.',
}: DomainListEditorProps) {
  const [draft, setDraft] = useState('');

  const add = () => {
    const value = draft.trim();
    if (!value) return;
    onAdd(value);
    setDraft('');
  };

  return (
    <div className={`space-y-2 ${disabled ? 'opacity-50 pointer-events-none' : ''}`}>
      <div className="flex gap-2">
        <input
          type="text"
          value={draft}
          onChange={(e) => setDraft(e.target.value)}
          onKeyDown={(e) => {
            if (e.key === 'Enter') {
              e.preventDefault();
              add();
            }
          }}
          placeholder="corp.example.com"
          disabled={disabled}
          className="flex-1 px-3 py-2 border border-hairline-strong rounded-lg text-sm
                     placeholder:text-faint focus:outline-none focus:ring-2
                     focus:ring-certus-500 focus:border-certus-500"
        />
        <button
          type="button"
          onClick={add}
          disabled={disabled || !draft.trim()}
          className="inline-flex items-center gap-2 px-4 py-2 text-sm font-medium
                     text-certus-700 dark:text-certus-300 bg-certus-50 dark:bg-certus-500/10 border border-certus-200 dark:border-certus-500/30 rounded-lg
                     hover:bg-certus-100 dark:bg-certus-500/15 disabled:opacity-50 transition-colors"
        >
          <Plus className="h-4 w-4" />
          Add
        </button>
        {extraAction}
      </div>

      {domains.length > 0 ? (
        <ul className="divide-y divide-hairline-soft border border-hairline rounded-lg">
          {domains.map((domain) => (
            <li key={domain} className="flex items-center gap-3 px-3 py-2">
              <span className="text-sm font-mono text-ink">{domain}</span>
              <span className="text-xs text-faint mr-auto">includes subdomains</span>
              <button
                type="button"
                onClick={() => onRemove(domain)}
                disabled={disabled}
                className="text-faint hover:text-red-600 transition-colors"
                title={`Remove ${domain}`}
                aria-label={`Remove ${domain}`}
              >
                <X className="h-4 w-4" />
              </button>
            </li>
          ))}
        </ul>
      ) : (
        <p className="text-xs text-faint border border-dashed border-hairline rounded-lg px-3 py-2">
          {emptyText}
        </p>
      )}
    </div>
  );
}
