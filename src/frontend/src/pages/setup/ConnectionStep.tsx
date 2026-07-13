import { useState, useEffect } from 'react';
import { CheckCircle2, XCircle, Loader2, Server, PencilLine } from 'lucide-react';
import { discoverCas, testCaConnection, type DiscoveredCa } from '@/api/setup';
import type { WizardState } from './SetupWizard';

interface ConnectionStepProps {
  state: WizardState;
  onUpdate: (updates: Partial<WizardState>) => void;
}

/**
 * CA selection and connectivity test. Enterprise CAs published in AD are
 * offered as a pick list (a forest can have several); manual entry is always
 * available for hosts where discovery finds nothing. The test probes the
 * chosen connection string through the service's real COM path — nothing is
 * persisted until the final step.
 */
export function ConnectionStep({ state, onUpdate }: ConnectionStepProps) {
  const [discovered, setDiscovered] = useState<DiscoveredCa[]>([]);
  const [discovering, setDiscovering] = useState(true);
  const [candidate, setCandidate] = useState(state.caConnectionString);
  const [useManual, setUseManual] = useState(false);
  const [manualEntry, setManualEntry] = useState('');
  const [testing, setTesting] = useState(false);
  const [error, setError] = useState<string | null>(null);

  useEffect(() => {
    discoverCas()
      .then((cas) => {
        setDiscovered(cas);
        // Prefill: an earlier saved value (the recovery path) wins; otherwise a
        // single discovered CA is the obvious default.
        const saved = state.caConnectionString;
        if (saved && !cas.some((ca) => ca.connectionString === saved)) {
          setUseManual(true);
          setManualEntry(saved);
        } else if (!saved && cas.length === 1) {
          setCandidate(cas[0].connectionString);
        } else if (!saved && cas.length === 0) {
          setUseManual(true);
        }
      })
      .catch(() => {
        setDiscovered([]);
        setUseManual(true);
      })
      .finally(() => setDiscovering(false));
    // Run once on mount; the saved value only matters for the initial prefill.
    // eslint-disable-next-line react-hooks/exhaustive-deps
  }, []);

  const effectiveCandidate = (useManual ? manualEntry : candidate).trim();

  const pickDiscovered = (connectionString: string) => {
    setUseManual(false);
    setCandidate(connectionString);
    setError(null);
    onUpdate({ connectionTested: false });
  };

  const pickManual = () => {
    setUseManual(true);
    setError(null);
    onUpdate({ connectionTested: false });
  };

  const handleTest = async () => {
    setTesting(true);
    setError(null);

    try {
      const result = await testCaConnection(effectiveCandidate);

      if (result.success) {
        onUpdate({
          connectionTested: true,
          caName: result.caName ?? '',
          caDnsName: result.caDnsName ?? '',
          caConnectionString: effectiveCandidate,
        });
      } else {
        setError(result.errorMessage ?? 'Connection test failed');
        onUpdate({ connectionTested: false });
      }
    } catch (err) {
      setError(err instanceof Error ? err.message : 'Connection test failed');
      onUpdate({ connectionTested: false });
    } finally {
      setTesting(false);
    }
  };

  return (
    <div className="space-y-6">
      <div>
        <h2 className="text-xl font-bold text-slate-900">Connect to Certificate Authority</h2>
        <p className="text-sm text-slate-500 mt-1">
          Pick the ADCS CA to issue certificates from, then test the connection. Ducks in a
          Row connects over DCOM/RPC, which requires this server to be domain joined with
          appropriate permissions on the CA.
        </p>
      </div>

      {discovering && (
        <div className="flex items-center gap-2 text-sm text-slate-500 py-4">
          <Loader2 className="h-4 w-4 animate-spin" />
          Looking for certificate authorities in Active Directory...
        </div>
      )}

      {!discovering && (
        <div className="space-y-2">
          {discovered.map((ca) => {
            const isSelected = !useManual && candidate === ca.connectionString;
            return (
              <label
                key={ca.connectionString}
                className={`flex items-center gap-3 p-3 rounded-xl border cursor-pointer transition-colors ${
                  isSelected
                    ? 'border-certus-300 bg-certus-50'
                    : 'border-slate-200 bg-white hover:border-slate-300'
                }`}
              >
                <input
                  type="radio"
                  name="ca"
                  checked={isSelected}
                  onChange={() => pickDiscovered(ca.connectionString)}
                  className="h-4 w-4 text-certus-600 border-slate-300 focus:ring-certus-500"
                />
                <Server className={`h-4 w-4 ${isSelected ? 'text-certus-600' : 'text-slate-400'}`} />
                <div className="flex-1 min-w-0">
                  <div className="text-sm font-medium text-slate-900">{ca.displayName}</div>
                  <div className="text-xs text-slate-500 font-mono">{ca.connectionString}</div>
                </div>
              </label>
            );
          })}

          <label
            className={`flex items-center gap-3 p-3 rounded-xl border cursor-pointer transition-colors ${
              useManual
                ? 'border-certus-300 bg-certus-50'
                : 'border-slate-200 bg-white hover:border-slate-300'
            }`}
          >
            <input
              type="radio"
              name="ca"
              checked={useManual}
              onChange={pickManual}
              className="h-4 w-4 text-certus-600 border-slate-300 focus:ring-certus-500"
            />
            <PencilLine className={`h-4 w-4 ${useManual ? 'text-certus-600' : 'text-slate-400'}`} />
            <div className="flex-1 min-w-0">
              <div className="text-sm font-medium text-slate-900">Enter manually</div>
              {discovered.length === 0 && (
                <div className="text-xs text-slate-500">
                  No CA was discovered in Active Directory. Find the connection string with{' '}
                  <code className="bg-slate-100 px-1 rounded">certutil -config - -ping</code>
                </div>
              )}
            </div>
          </label>

          {useManual && (
            <input
              type="text"
              value={manualEntry}
              onChange={(e) => {
                setManualEntry(e.target.value);
                setError(null);
                onUpdate({ connectionTested: false });
              }}
              placeholder="CAHOST.corp.example.com\Corp Issuing CA"
              spellCheck={false}
              className="w-full px-3 py-2 text-sm font-mono border border-slate-300 rounded-lg
                         focus:outline-none focus:ring-2 focus:ring-certus-500 focus:border-certus-500"
            />
          )}
        </div>
      )}

      <div className="bg-slate-50 border border-slate-200 rounded-lg p-4">
        <div className="flex items-start gap-3">
          <Server className="h-5 w-5 text-slate-400 mt-0.5" />
          <p className="text-xs text-slate-500">
            The service account running Ducks in a Row needs <strong>Request Certificates</strong>{' '}
            permission on the CA and the relevant templates.
          </p>
        </div>
      </div>

      <div className="flex items-center gap-3">
        <button
          onClick={handleTest}
          disabled={testing || discovering || effectiveCandidate.length === 0}
          className="inline-flex items-center gap-2 px-4 py-2 text-sm font-medium text-white
                     bg-certus-600 rounded-lg hover:bg-certus-700 disabled:opacity-50 transition-colors"
        >
          {testing ? (
            <>
              <Loader2 className="h-4 w-4 animate-spin" />
              Testing...
            </>
          ) : (
            <>
              <Server className="h-4 w-4" />
              Test CA Connection
            </>
          )}
        </button>
      </div>

      {/* Success */}
      {state.connectionTested && (
        <div className="bg-emerald-50 border border-emerald-200 rounded-lg p-4">
          <div className="flex items-start gap-3">
            <CheckCircle2 className="h-5 w-5 text-emerald-600 mt-0.5" />
            <div>
              <h3 className="text-sm font-semibold text-emerald-900">Connected successfully</h3>
              <dl className="mt-2 text-sm text-emerald-800 space-y-1">
                <div className="flex gap-2">
                  <dt className="font-medium">CA Name:</dt>
                  <dd>{state.caName}</dd>
                </div>
                <div className="flex gap-2">
                  <dt className="font-medium">DNS Name:</dt>
                  <dd>{state.caDnsName}</dd>
                </div>
                <div className="flex gap-2">
                  <dt className="font-medium">Connection String:</dt>
                  <dd className="font-mono text-xs">{state.caConnectionString}</dd>
                </div>
              </dl>
            </div>
          </div>
        </div>
      )}

      {/* Error */}
      {error && (
        <div className="bg-red-50 border border-red-200 rounded-lg p-4">
          <div className="flex items-start gap-3">
            <XCircle className="h-5 w-5 text-red-600 mt-0.5" />
            <div>
              <h3 className="text-sm font-semibold text-red-900">Connection failed</h3>
              <p className="text-sm text-red-700 mt-1">{error}</p>
              <p className="text-xs text-red-500 mt-2">
                Verify that this server is domain joined and the CA is reachable via RPC.
              </p>
            </div>
          </div>
        </div>
      )}
    </div>
  );
}
