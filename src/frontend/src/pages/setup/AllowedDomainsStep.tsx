import type { ReactNode } from 'react';
import { AlertTriangle } from 'lucide-react';
import { DomainListEditor } from '@/components/DomainListEditor';
import type { WizardState } from './SetupWizard';

interface AllowedDomainsStepProps {
  state: WizardState;
  onUpdate: (updates: Partial<WizardState>) => void;
}

/** The one line an administrator sees when they switch a control off. */
function OffWarning({ children }: { children: ReactNode }) {
  return (
    <div className="bg-amber-50 dark:bg-amber-500/10 border border-amber-200 dark:border-amber-500/30 rounded-lg p-3 flex items-start gap-2">
      <AlertTriangle className="h-4 w-4 text-amber-600 mt-0.5 shrink-0" />
      <p className="text-xs text-amber-800 dark:text-amber-300">{children}</p>
    </div>
  );
}

/**
 * The wizard's Client Access step: the two controls that decide who can get a
 * certificate, both on by default on a fresh install (issue #631, Sean's
 * decision). External account binding arrives required, so only a client an
 * administrator handed a credential can register. The domain restriction
 * arrives on with the AD domain in the list on a domain joined server, and off
 * with an empty list in a workgroup, where there is nothing to suggest.
 * Switching either off is an explicit choice, and each says in one line what
 * it gives up. Entries are validated server side at completion, where the
 * normalization rules live.
 *
 * Monitor mode skips this step: it issues nothing, so it has no client to
 * admit and no domain to restrict.
 */
export function AllowedDomainsStep({ state, onUpdate }: AllowedDomainsStepProps) {
  const suggestion = state.adDomainSuggestion;
  const showSuggestionButton =
    suggestion !== null && !state.allowedDomains.includes(suggestion);
  const bindingRequired = state.eabEnforcement === 'required';

  const add = (domain: string) => {
    if (!state.allowedDomains.includes(domain)) {
      onUpdate({ allowedDomains: [...state.allowedDomains, domain] });
    }
  };

  return (
    <div className="space-y-6">
      <div>
        <h2 className="text-xl font-bold text-ink">Client Access</h2>
        <p className="text-sm text-muted mt-1">
          Choose which ACME clients may register with this server, and which
          domains it may issue certificates for.
        </p>
      </div>

      <section className="space-y-3">
        <h3 className="text-sm font-semibold text-ink">External account binding</h3>
        <label className="flex items-start gap-3 cursor-pointer">
          <input
            type="checkbox"
            checked={bindingRequired}
            onChange={(e) => onUpdate({ eabEnforcement: e.target.checked ? 'required' : 'off' })}
            className="mt-0.5 h-4 w-4 rounded border-hairline-strong text-certus-600 focus:ring-certus-500"
          />
          <span className="text-sm font-medium text-ink">
            Require a credential to register an ACME account (recommended)
            <span className="block text-xs font-normal text-muted mt-0.5">
              Before a client can get its first certificate, you create a
              credential for it on the ACME page and give it the key ID and
              HMAC key. You can change this later on the ACME page, and the
              change applies without a restart.
            </span>
          </span>
        </label>

        {state.eabEnforcement === 'optional' && (
          <p className="text-xs text-muted">
            This server records binding as optional: a credential is checked
            when a client presents one, and a client without one can still
            register. Tick the box to require it.
          </p>
        )}

        {!bindingRequired && (
          <OffWarning>
            Without a required credential, anyone who can reach this server can
            register and order a certificate for any name they can prove they
            control.
          </OffWarning>
        )}
      </section>

      <section className="space-y-3">
        <h3 className="text-sm font-semibold text-ink">Allowed domains</h3>
        <label className="flex items-start gap-3 cursor-pointer">
          <input
            type="checkbox"
            checked={state.allowedDomainsEnabled}
            onChange={(e) => onUpdate({ allowedDomainsEnabled: e.target.checked })}
            className="mt-0.5 h-4 w-4 rounded border-hairline-strong text-certus-600 focus:ring-certus-500"
          />
          <span className="text-sm font-medium text-ink">
            Restrict certificate issuance to these domains (recommended)
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

        {!state.allowedDomainsEnabled && (
          <OffWarning>
            With the restriction off, ACME clients can order a certificate for
            any name that passes challenge validation, including names outside
            your organization.
          </OffWarning>
        )}

        {state.allowedDomainsEnabled && state.allowedDomains.length === 0 && (
          <OffWarning>Add at least one domain, or turn the restriction off.</OffWarning>
        )}

        <div className="bg-sunken border border-hairline rounded-lg p-3">
          <p className="text-xs text-muted">
            An entry covers the domain and all of its subdomains:
            corp.example.com also allows web.corp.example.com, so wildcard
            entries are not needed.
            This restricts issuance through Ducks in a Row only; the
            certificate authority itself can still issue for any name through
            its own tools. You can change the list later on the Settings page,
            and changes apply without a restart.
          </p>
        </div>
      </section>
    </div>
  );
}
