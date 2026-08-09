import { useState } from 'react';
import { useQuery, useQueryClient } from '@tanstack/react-query';
import { AlertTriangle, CheckCircle2, Loader2, ShieldOff, X } from 'lucide-react';
import {
  fetchRevocationScope,
  updateRevocationScope,
  type InvalidTemplateEntry,
  type RevocationScopeMode,
} from '@/api/settings';
import { useTemplates } from '@/hooks/useCertificates';
import type { CertificateTemplate } from '@/types';

const modeOptions: {
  value: RevocationScopeMode;
  label: string;
  description: string;
}[] = [
  {
    value: 'ducks-managed',
    label: 'Ducks managed templates (recommended)',
    description:
      'Certificates Ducks issued through ACME, plus certificates on the templates enabled for ACME. Everything else in the inventory is view only.',
  },
  {
    value: 'custom',
    label: 'Selected templates',
    description:
      'Certificates on the templates checked below, whoever enrolled them. An empty selection disables revocation from the dashboard entirely.',
  },
  {
    value: 'all',
    label: 'All templates',
    description:
      'Any certificate in the CA database that the TLS guardrail allows.',
  },
];

/**
 * Case insensitive match of a stored entry against a template's two forms.
 * Plain toLowerCase rather than a locale aware comparison: the server
 * matches with OrdinalIgnoreCase, and the admin's browser locale must not
 * make the checkbox state disagree with what the server enforces.
 */
function entryMatchesTemplate(entry: string, template: CertificateTemplate): boolean {
  const lower = entry.toLowerCase();
  return (
    lower === template.name.toLowerCase() ||
    lower === template.displayName.toLowerCase()
  );
}

/** Whether two entry lists hold the same names, ignoring order. */
function sameEntries(a: string[], b: string[]): boolean {
  if (a.length !== b.length) return false;
  const sortedA = [...a].sort();
  const sortedB = [...b].sort();
  return sortedA.every((value, index) => value === sortedB[index]);
}

/**
 * Settings card for the dashboard revocation scope. The three modes only
 * ever narrow within the TLS guardrail, which is unconditional; the server
 * enforces the scope on the revoke endpoint, so this card is configuration,
 * not the gate itself. Changes apply to the next revocation attempt
 * immediately: the policy hot reads the wizard status file, so there is no
 * restart flow.
 */
export function RevocationScopeCard() {
  const queryClient = useQueryClient();

  const { data: settings, isLoading, isError } = useQuery({
    queryKey: ['settings', 'revocation-scope'],
    queryFn: fetchRevocationScope,
    staleTime: 30_000,
    retry: false,
  });
  const { data: templates, isLoading: templatesLoading } = useTemplates();

  // null until the admin edits; the card shows the loaded values until then
  // (the AllowedDomainsCard local edit overlay pattern).
  const [modeEdit, setModeEdit] = useState<RevocationScopeMode | null>(null);
  const [customEdit, setCustomEdit] = useState<string[] | null>(null);
  const [saving, setSaving] = useState(false);
  const [error, setError] = useState<string | null>(null);
  const [invalidEntries, setInvalidEntries] = useState<InvalidTemplateEntry[]>([]);
  const [savedMessage, setSavedMessage] = useState<string | null>(null);

  const mode = modeEdit ?? settings?.mode ?? 'ducks-managed';
  const customTemplates = customEdit ?? settings?.customTemplates ?? [];
  // Order insensitive: unticking and re-ticking a template rebuilds the
  // list in a different order, which is not a change worth a Save.
  const dirty =
    mode !== (settings?.mode ?? 'ducks-managed') ||
    !sameEntries(customTemplates, settings?.customTemplates ?? []);

  // Stored entries no current CA template matches under either name form:
  // legitimately possible (the template was unpublished), kept on save, and
  // removable here. With no template list at all (the CA is unreachable)
  // every stored entry renders this way, so the admin can still see and
  // edit the configured scope.
  const templatesLoaded = templates !== undefined;
  const unmatchedEntries = templatesLoaded
    ? customTemplates.filter((entry) => !templates.some((t) => entryMatchesTemplate(entry, t)))
    : customTemplates;

  const clearFeedback = () => {
    setError(null);
    setInvalidEntries([]);
    setSavedMessage(null);
  };

  const handleSelectMode = (value: RevocationScopeMode) => {
    clearFeedback();
    setModeEdit(value);
  };

  const handleToggleTemplate = (template: CertificateTemplate, checked: boolean) => {
    clearFeedback();
    const without = customTemplates.filter((entry) => !entryMatchesTemplate(entry, template));
    // Ticking stores the canonical name; the server accepts either form.
    setCustomEdit(checked ? [...without, template.name] : without);
  };

  const handleRemoveEntry = (entry: string) => {
    clearFeedback();
    setCustomEdit(customTemplates.filter((e) => e !== entry));
  };

  const handleSave = async () => {
    setSaving(true);
    clearFeedback();
    try {
      const outcome = await updateRevocationScope(mode, customTemplates);
      if (outcome.kind === 'invalid') {
        setError(outcome.error);
        setInvalidEntries(outcome.invalidEntries);
        return;
      }
      setSavedMessage(outcome.message);
      // Refetch first, then drop the local edits, so the card lands on the
      // server's values without flashing the pre save state.
      await queryClient.invalidateQueries({ queryKey: ['settings', 'revocation-scope'] });
      setModeEdit(null);
      setCustomEdit(null);
    } catch (err) {
      setError(err instanceof Error ? err.message : 'Saving failed');
    } finally {
      setSaving(false);
    }
  };

  return (
    <div className="bg-surface border border-hairline rounded-lg p-6 space-y-4">
      <div className="flex items-center gap-2">
        <ShieldOff className="h-4 w-4 text-certus-600" />
        <h3 className="text-sm font-semibold text-ink">Revocation scope</h3>
      </div>
      <p className="text-sm text-muted">
        Which certificates the Revoke button on a certificate page may act
        on. The TLS guardrail applies above every mode: identity, signing,
        and CA certificates are never revocable from here. Changes apply
        immediately, no restart needed.
      </p>

      {isLoading ? (
        <div className="flex items-center gap-2 text-sm text-faint py-2">
          <Loader2 className="h-4 w-4 animate-spin" />
          Loading current configuration…
        </div>
      ) : isError ? (
        <div className="bg-red-50 dark:bg-red-500/10 border border-red-200 dark:border-red-500/30 rounded-lg p-3 flex items-start gap-2">
          <AlertTriangle className="h-4 w-4 text-red-500 mt-0.5" />
          <p className="text-xs text-red-700 dark:text-red-300">
            The current revocation scope could not be loaded. Check the
            service log; a ducks-setup.json in the data directory that is not
            valid JSON must be fixed by hand.
          </p>
        </div>
      ) : (
        <>
          <div className="space-y-2">
            {modeOptions.map((option) => (
              <label
                key={option.value}
                className={`flex items-start gap-3 rounded-lg border p-3 cursor-pointer transition-colors ${
                  mode === option.value
                    ? 'border-certus-300 bg-certus-50 dark:bg-certus-500/10'
                    : 'border-hairline hover:bg-sunken'
                }`}
              >
                <input
                  type="radio"
                  name="revocation-scope-mode"
                  checked={mode === option.value}
                  onChange={() => handleSelectMode(option.value)}
                  className="mt-0.5 h-4 w-4 border-hairline-strong text-certus-600 focus:ring-certus-500"
                />
                <span className="text-sm font-medium text-ink">
                  {option.label}
                  <span className="block text-xs font-normal text-muted mt-0.5">
                    {option.description}
                  </span>
                </span>
              </label>
            ))}
          </div>

          {mode === 'custom' && (
            <>
              <div className="space-y-1.5">
                {(templates ?? []).map((template) => {
                  const stored = customTemplates.some((entry) =>
                    entryMatchesTemplate(entry, template));
                  const blocked = template.tlsCapable === false;
                  // A stored entry on a blocked template stays interactive
                  // so it can still be unticked; only adding one is refused.
                  const locked = blocked && !stored;
                  return (
                    <label
                      key={template.oid || template.name}
                      title={blocked ? template.tlsBlockedReason ?? undefined : undefined}
                      className={`flex items-start gap-3 rounded-lg border border-hairline p-2.5 ${
                        locked ? 'opacity-50 cursor-not-allowed' : 'cursor-pointer hover:bg-sunken'
                      }`}
                    >
                      <input
                        type="checkbox"
                        checked={stored}
                        disabled={locked}
                        onChange={(e) => handleToggleTemplate(template, e.target.checked)}
                        className="mt-0.5 h-4 w-4 rounded border-hairline-strong text-certus-600 focus:ring-certus-500"
                      />
                      <span className="text-sm text-ink">
                        {template.displayName || template.name}
                        <span className="ml-1.5 text-xs text-faint">({template.name})</span>
                        {blocked && (
                          <span className="block text-xs text-muted mt-0.5">
                            Blocked by the TLS guardrail: {template.tlsBlockedReason}
                          </span>
                        )}
                      </span>
                    </label>
                  );
                })}
                {templatesLoading && (
                  <p className="flex items-center gap-2 text-xs text-faint py-1">
                    <Loader2 className="h-3 w-3 animate-spin" />
                    Loading the CA template list…
                  </p>
                )}
                {!templatesLoading && !templatesLoaded && (
                  <p className="text-xs text-faint py-1">
                    The CA template list could not be loaded right now. The
                    stored entries are shown below and can be removed; reload
                    the page to retry.
                  </p>
                )}
                {templatesLoaded && templates.length === 0 && (
                  <p className="text-xs text-faint py-1">
                    No templates could be read from the CA right now.
                  </p>
                )}
              </div>

              {unmatchedEntries.length > 0 && (
                <div className="flex flex-wrap items-center gap-1.5">
                  {unmatchedEntries.map((entry) => (
                    <span
                      key={entry}
                      className="inline-flex items-center gap-1 rounded bg-sunken-strong px-2 py-0.5 text-xs text-ink-soft"
                    >
                      {entry}
                      {templatesLoaded && (
                        <span className="text-faint">(not currently published on the CA)</span>
                      )}
                      <button
                        type="button"
                        onClick={() => handleRemoveEntry(entry)}
                        aria-label={`Remove ${entry}`}
                        className="hover:text-ink"
                      >
                        <X className="h-3 w-3" />
                      </button>
                    </span>
                  ))}
                </div>
              )}

              <div className="bg-amber-50 dark:bg-amber-500/10 border border-amber-200 dark:border-amber-500/30 rounded-lg p-3 flex items-start gap-2">
                <AlertTriangle className="h-4 w-4 text-amber-600 mt-0.5" />
                <p className="text-xs text-amber-800 dark:text-amber-300">
                  Any certificate on a checked template becomes revocable from
                  this dashboard, including certificates other systems
                  enrolled. Revoking a certificate another service depends on
                  takes that service down until it re-enrolls.
                </p>
              </div>
            </>
          )}

          {mode === 'all' && (
            <div className="bg-red-50 dark:bg-red-500/10 border border-red-200 dark:border-red-500/30 rounded-lg p-3 flex items-start gap-2">
              <AlertTriangle className="h-4 w-4 text-red-500 mt-0.5" />
              <p className="text-xs text-red-700 dark:text-red-300">
                Any certificate in the CA database that passes the TLS
                guardrail becomes revocable from this dashboard. The guardrail
                cannot see what a certificate is used for: an old style domain
                controller TLS certificate carrying only the server and client
                authentication usages passes it, and revoking one can break
                LDAPS for that domain controller. Prefer the selected
                templates mode unless this console is meant to manage the
                whole CA.
              </p>
            </div>
          )}

          <div className="flex items-center justify-end">
            <button
              onClick={handleSave}
              disabled={saving || !dirty}
              className="inline-flex items-center gap-2 px-4 py-2 text-sm font-medium text-white
                         bg-certus-600 rounded-lg hover:bg-certus-700 disabled:opacity-50
                         transition-colors"
            >
              {saving ? <Loader2 className="h-4 w-4 animate-spin" /> : 'Save'}
            </button>
          </div>

          {savedMessage && (
            <div className="bg-emerald-50 dark:bg-emerald-500/10 border border-emerald-200 dark:border-emerald-500/30 rounded-lg p-3 flex items-start gap-2">
              <CheckCircle2 className="h-4 w-4 text-emerald-600 mt-0.5" />
              <p className="text-xs text-emerald-800 dark:text-emerald-300">{savedMessage}</p>
            </div>
          )}

          {error && (
            <div className="bg-red-50 dark:bg-red-500/10 border border-red-200 dark:border-red-500/30 rounded-lg p-3 flex items-start gap-2">
              <AlertTriangle className="h-4 w-4 text-red-500 mt-0.5" />
              <div className="text-xs text-red-700 dark:text-red-300">
                <p>{error}</p>
                {invalidEntries.length > 0 && (
                  <ul className="mt-1 list-disc list-inside">
                    {invalidEntries.map((entry) => (
                      <li key={entry.entry}>
                        {entry.entry}: {entry.reason}
                      </li>
                    ))}
                  </ul>
                )}
              </div>
            </div>
          )}
        </>
      )}
    </div>
  );
}
