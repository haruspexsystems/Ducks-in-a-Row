import { useState } from 'react';
import { useQuery, useQueryClient } from '@tanstack/react-query';
import { AlertTriangle, CheckCircle2, Loader2, ShieldCheck } from 'lucide-react';
import {
  fetchEabEnforcement,
  updateEabEnforcement,
  type EabEnforcementMode,
} from '@/api/acme';

const modeOptions: {
  value: EabEnforcementMode;
  label: string;
  description: string;
}[] = [
  {
    value: 'off',
    label: 'Off',
    description: 'Anyone who can reach the server can register an ACME account. A presented binding is ignored.',
  },
  {
    value: 'optional',
    label: 'Optional',
    description: 'A presented binding is verified and recorded; registration without one is still allowed. The migration stage while credentials are handed out.',
  },
  {
    value: 'required',
    label: 'Required',
    description: 'New registrations must present a valid EAB credential. Clients without one are refused.',
  },
];

/**
 * Dashboard card for the EAB enforcement mode (RFC 8555 section 7.3.4).
 * Changes apply to the next ACME request immediately: the policy hot reads
 * the wizard status file, so there is no restart flow. Under Required,
 * accounts that already exist without a binding are grandfathered; the
 * amber note says how many there are, and the Accounts tab is where an
 * administrator reviews and deactivates them.
 */
export function EabEnforcementCard() {
  const queryClient = useQueryClient();

  const { data: settings, isLoading, isError } = useQuery({
    queryKey: ['acme', 'eab-enforcement'],
    queryFn: fetchEabEnforcement,
    staleTime: 30_000,
    retry: false,
  });

  // null until the admin picks a different mode; the card shows the loaded
  // value until then (the AllowedDomainsCard local edit overlay pattern).
  const [modeEdit, setModeEdit] = useState<EabEnforcementMode | null>(null);
  const [saving, setSaving] = useState(false);
  const [error, setError] = useState<string | null>(null);
  const [savedMessage, setSavedMessage] = useState<string | null>(null);

  const mode = modeEdit ?? settings?.mode ?? 'off';
  const dirty = mode !== (settings?.mode ?? 'off');
  const unboundAccounts = settings?.unboundAccounts ?? 0;

  const handleSelect = (value: EabEnforcementMode) => {
    setError(null);
    setSavedMessage(null);
    setModeEdit(value);
  };

  const handleSave = async () => {
    setSaving(true);
    setError(null);
    setSavedMessage(null);
    try {
      const result = await updateEabEnforcement(mode);
      setSavedMessage(result.message);
      // Refetch first, then drop the local edit, so the card lands on the
      // server's value without flashing the pre save state.
      await queryClient.invalidateQueries({ queryKey: ['acme', 'eab-enforcement'] });
      setModeEdit(null);
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
        <h3 className="text-sm font-semibold text-ink">External Account Binding</h3>
      </div>
      <p className="text-sm text-muted">
        Require ACME clients to present a pre-issued credential when they
        register (RFC 8555 external account binding). Create and hand out
        credentials in the card below. Changes apply immediately, no restart
        needed.
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
            The current enforcement mode could not be loaded. Check the
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
                  name="eab-mode"
                  checked={mode === option.value}
                  onChange={() => handleSelect(option.value)}
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

          {mode === 'required' && (
            <div className="bg-amber-50 dark:bg-amber-500/10 border border-amber-200 dark:border-amber-500/30 rounded-lg p-3 flex items-start gap-2">
              <AlertTriangle className="h-4 w-4 text-amber-600 mt-0.5" />
              <p className="text-xs text-amber-800 dark:text-amber-300">
                {unboundAccounts === 0
                  ? 'Accounts that already exist without a binding are grandfathered: they keep working. There are currently none.'
                  : `${unboundAccounts} existing account${unboundAccounts === 1 ? ' is' : 's are'} grandfathered: ${unboundAccounts === 1 ? 'it has' : 'they have'} no binding and will keep working. Review ${unboundAccounts === 1 ? 'it' : 'them'} on the Accounts tab, with status Valid and binding Unbound, and deactivate any that should not.`}
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
              <p className="text-xs text-red-700 dark:text-red-300">{error}</p>
            </div>
          )}
        </>
      )}
    </div>
  );
}
