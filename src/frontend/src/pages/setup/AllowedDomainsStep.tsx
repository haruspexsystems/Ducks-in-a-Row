import { AlertTriangle } from 'lucide-react';
import { DomainListEditor } from '@/components/DomainListEditor';
import type { WizardState } from './SetupWizard';

interface AllowedDomainsStepProps {
  state: WizardState;
  onUpdate: (updates: Partial<WizardState>) => void;
}

/**
 * The wizard's domain restriction step. On a domain joined server the
 * wizard arrives here with the restriction on and the AD domain already in
 * the list (the secure default for new installs); in a workgroup it arrives
 * off with an empty list. Entries are validated server side at completion,
 * where the normalization rules live.
 */
export function AllowedDomainsStep({ state, onUpdate }: AllowedDomainsStepProps) {
  const suggestion = state.adDomainSuggestion;
  const showSuggestionButton =
    suggestion !== null && !state.allowedDomains.includes(suggestion);

  const add = (domain: string) => {
    if (!state.allowedDomains.includes(domain)) {
      onUpdate({ allowedDomains: [...state.allowedDomains, domain] });
    }
  };

  return (
    <div className="space-y-6">
      <div>
        <h2 className="text-xl font-bold text-ink">Allowed Domains</h2>
        <p className="text-sm text-muted mt-1">
          Choose which domains this server may issue certificates for.
        </p>
      </div>

      <label className="flex items-start gap-3 cursor-pointer">
        <input
          type="checkbox"
          checked={state.allowedDomainsEnabled}
          onChange={(e) => onUpdate({ allowedDomainsEnabled: e.target.checked })}
          className="mt-0.5 h-4 w-4 rounded border-hairline-strong text-certus-600 focus:ring-certus-500"
        />
        <span className="text-sm font-medium text-ink">
          Restrict certificate issuance to these domains (recommended)
          <span className="block text-xs font-normal text-muted mt-0.5">
            When off, ACME clients can order a certificate for any name that
            passes challenge validation, including names outside your
            organization.
          </span>
        </span>
      </label>

      <DomainListEditor
        domains={state.allowedDomains}
        onAdd={add}
        onRemove={(domain) =>
          onUpdate({ allowedDomains: state.allowedDomains.filter((d) => d !== domain) })
        }
        disabled={!state.allowedDomainsEnabled}
        extraAction={
          showSuggestionButton ? (
            <button
              type="button"
              onClick={() => add(suggestion)}
              className="inline-flex items-center gap-2 px-4 py-2 text-sm font-medium
                         text-certus-700 dark:text-certus-300 bg-certus-50 dark:bg-certus-500/10 border border-certus-200 dark:border-certus-500/30 rounded-lg
                         hover:bg-certus-100 dark:bg-certus-500/15 whitespace-nowrap transition-colors"
            >
              Add {suggestion}
            </button>
          ) : undefined
        }
      />

      {state.allowedDomainsEnabled && state.allowedDomains.length === 0 && (
        <div className="bg-amber-50 dark:bg-amber-500/10 border border-amber-200 dark:border-amber-500/30 rounded-lg p-3 flex items-start gap-2">
          <AlertTriangle className="h-4 w-4 text-amber-600 mt-0.5" />
          <p className="text-xs text-amber-800 dark:text-amber-300">
            Add at least one domain, or turn the restriction off.
          </p>
        </div>
      )}

      <div className="bg-sunken border border-hairline rounded-lg p-3">
        <p className="text-xs text-muted">
          An entry covers the domain and all of its subdomains: home.local
          also allows web.home.local, so wildcard entries are not needed.
          This restricts issuance through Ducks in a Row only; the
          certificate authority itself can still issue for any name through
          its own tools. You can change the list later on the Settings page,
          and changes apply without a restart.
        </p>
      </div>
    </div>
  );
}
