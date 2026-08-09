import { useState } from 'react';
import { useQuery, useQueryClient } from '@tanstack/react-query';
import { AlertTriangle, CheckCircle2, Loader2, ShieldCheck } from 'lucide-react';
import {
  fetchAllowedDomainsSettings,
  updateAllowedDomains,
  type InvalidDomainEntry,
} from '@/api/settings';
import { DomainListEditor } from '@/components/DomainListEditor';

/**
 * Dashboard card for the allowed domain policy: restrict certificate
 * issuance to a list of domains, each entry covering the domain and all of
 * its subdomains. Edits apply immediately because the issuance policy hot
 * reads the file, so unlike the external URL card there is no restart flow.
 */
export function AllowedDomainsCard() {
  const queryClient = useQueryClient();

  const { data: settings, isLoading, isError } = useQuery({
    queryKey: ['settings', 'allowed-domains'],
    queryFn: fetchAllowedDomainsSettings,
    staleTime: 30_000,
    retry: false,
  });

  // null until the admin edits; the card shows the loaded values until then.
  const [enabledEdit, setEnabledEdit] = useState<boolean | null>(null);
  const [domainsEdit, setDomainsEdit] = useState<string[] | null>(null);
  const [saving, setSaving] = useState(false);
  const [error, setError] = useState<string | null>(null);
  const [invalidEntries, setInvalidEntries] = useState<InvalidDomainEntry[]>([]);
  const [savedMessage, setSavedMessage] = useState<string | null>(null);

  const enabled = enabledEdit ?? settings?.enabled ?? false;
  const domains = domainsEdit ?? settings?.domains ?? [];
  const dirty =
    enabled !== (settings?.enabled ?? false) ||
    JSON.stringify(domains) !== JSON.stringify(settings?.domains ?? []);
  const enabledWithEmptyList = enabled && domains.length === 0;
  const adDomain = settings?.adDomain ?? null;
  const showAdDomainButton = adDomain !== null && !domains.includes(adDomain);

  const clearOutcome = () => {
    setError(null);
    setInvalidEntries([]);
    setSavedMessage(null);
  };

  const handleToggle = (value: boolean) => {
    clearOutcome();
    setEnabledEdit(value);
  };

  const handleAdd = (domain: string) => {
    clearOutcome();
    if (!domains.includes(domain)) setDomainsEdit([...domains, domain]);
  };

  const handleRemove = (domain: string) => {
    clearOutcome();
    setDomainsEdit(domains.filter((d) => d !== domain));
  };

  const handleSave = async () => {
    setSaving(true);
    clearOutcome();
    try {
      const outcome = await updateAllowedDomains(enabled, domains);
      if (outcome.kind === 'invalid') {
        setError(outcome.error);
        setInvalidEntries(outcome.invalidEntries);
        return;
      }
      setSavedMessage(outcome.result.message);
      // Refetch first, then drop the local edits, so the card lands on the
      // server's normalized list without flashing the pre save values.
      await queryClient.invalidateQueries({ queryKey: ['settings', 'allowed-domains'] });
      setEnabledEdit(null);
      setDomainsEdit(null);
    } catch (err) {
      setError(err instanceof Error ? err.message : 'Saving failed');
    } finally {
      setSaving(false);
    }
  };

  return (
    <div className="bg-surface border border-hairline rounded-lg p-6 space-y-4">
      <div className="flex items-center gap-2">
        <ShieldCheck className="h-4 w-4 text-certus-600" />
        <h3 className="text-sm font-semibold text-ink">Allowed Domains</h3>
      </div>
      <p className="text-sm text-muted">
        Restrict certificate issuance to your own domains. Each entry covers
        the domain and all of its subdomains. Changes apply immediately, no
        restart needed.
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
            The current allowed domain configuration could not be loaded.
            Check the service log; a ducks-setup.json in the data directory
            that is not valid JSON must be fixed by hand.
          </p>
        </div>
      ) : (
        <>
          <label className="flex items-start gap-3 cursor-pointer">
            <input
              type="checkbox"
              checked={enabled}
              onChange={(e) => handleToggle(e.target.checked)}
              className="mt-0.5 h-4 w-4 rounded border-hairline-strong text-certus-600 focus:ring-certus-500"
            />
            <span className="text-sm font-medium text-ink">
              Only issue certificates for the domains below
              <span className="block text-xs font-normal text-muted mt-0.5">
                When off, ACME clients can order a certificate for any name
                that passes challenge validation.
              </span>
            </span>
          </label>

          <DomainListEditor
            domains={domains}
            onAdd={handleAdd}
            onRemove={handleRemove}
            disabled={!enabled}
            extraAction={
              showAdDomainButton ? (
                <button
                  type="button"
                  onClick={() => handleAdd(adDomain)}
                  className="inline-flex items-center gap-2 px-4 py-2 text-sm font-medium
                             text-certus-700 dark:text-certus-300 bg-certus-50 dark:bg-certus-500/10 border border-certus-200 dark:border-certus-500/30 rounded-lg
                             hover:bg-certus-100 dark:bg-certus-500/15 whitespace-nowrap transition-colors"
                  title={`Add ${adDomain}`}
                >
                  Add my AD domain
                </button>
              ) : undefined
            }
          />

          {enabledWithEmptyList && (
            <div className="bg-amber-50 dark:bg-amber-500/10 border border-amber-200 dark:border-amber-500/30 rounded-lg p-3 flex items-start gap-2">
              <AlertTriangle className="h-4 w-4 text-amber-600 mt-0.5" />
              <p className="text-xs text-amber-800 dark:text-amber-300">
                Add at least one domain, or turn the restriction off.
              </p>
            </div>
          )}

          <div className="flex items-center justify-end">
            <button
              onClick={handleSave}
              disabled={saving || !dirty || enabledWithEmptyList}
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
              <div className="space-y-1">
                <p className="text-xs text-red-700 dark:text-red-300">{error}</p>
                {invalidEntries.length > 0 && (
                  <ul className="text-xs text-red-700 dark:text-red-300 list-disc list-inside space-y-0.5">
                    {invalidEntries.map((e) => (
                      <li key={e.entry}>
                        <code className="font-mono">{e.entry}</code>: {e.reason}
                      </li>
                    ))}
                  </ul>
                )}
              </div>
            </div>
          )}

          <p className="text-xs text-faint">
            This restricts issuance through Ducks in a Row only. The
            certificate authority itself can still issue for any name through
            its own tools, for example MMC or certreq.
          </p>
        </>
      )}
    </div>
  );
}
