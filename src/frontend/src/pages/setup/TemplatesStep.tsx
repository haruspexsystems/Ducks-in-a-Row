import { useState, useEffect } from 'react';
import {
  FileCheck2,
  Loader2,
  AlertTriangle,
  ShieldAlert,
  CheckCircle2,
  HelpCircle,
  Info,
} from 'lucide-react';
import { fetchSetupTemplates, type SetupTemplate } from '@/api/setup';
import type { WizardState } from './SetupWizard';

interface TemplatesStepProps {
  state: WizardState;
  onUpdate: (updates: Partial<WizardState>) => void;
}

export function TemplatesStep({ state, onUpdate }: TemplatesStepProps) {
  const [templates, setTemplates] = useState<SetupTemplate[]>([]);
  const [excludedCount, setExcludedCount] = useState(0);
  const [loading, setLoading] = useState(true);
  const [error, setError] = useState<string | null>(null);

  useEffect(() => {
    setLoading(true);
    fetchSetupTemplates(state.caConnectionString)
      .then((data) => {
        if (data && Array.isArray(data.templates)) {
          setTemplates(data.templates);
          setExcludedCount(data.excludedCount ?? 0);
        } else {
          setError('Failed to load templates');
        }
      })
      .catch((err) => setError(err.message))
      .finally(() => setLoading(false));
  }, [state.caConnectionString]);

  // Only one template may be selected (each Ducks in a Row deployment exposes a
  // single ACME directory). Selecting replaces any previous choice. The key
  // requirements travel to the review page so its client guidance can state
  // what the template actually requires.
  const selectTemplate = (template: SetupTemplate) => {
    onUpdate({
      selectedTemplates: [template.name],
      templateKeyAlgorithm: template.viability?.keyAlgorithm ?? null,
      templateMinimalKeySize: template.viability?.minimalKeySize ?? null,
    });
  };

  const selected = state.selectedTemplates[0];
  // When EKU could not be read from AD, the API returns every template flagged
  // unverified rather than an empty list. Surface that so the admin knows the
  // server authentication filter was not applied.
  const ekuUnverified = templates.length > 0 && templates.some((t) => !t.ekuVerified);

  return (
    <div className="space-y-6">
      <div>
        <h2 className="text-xl font-bold text-slate-900">Select a Certificate Template</h2>
        <p className="text-sm text-slate-500 mt-1">
          Choose the ADCS template to expose via ACME. Only templates that can issue
          server authentication certificates are listed. The template gets its own
          ACME directory URL: <code className="bg-slate-100 px-1 rounded text-xs">/acme/{'{'}<em>template</em>{'}'}/directory</code>
        </p>
      </div>

      {loading && (
        <div className="flex items-center justify-center py-12">
          <Loader2 className="h-6 w-6 text-certus-500 animate-spin" />
          <span className="text-sm text-slate-500 ml-2">Loading templates from CA...</span>
        </div>
      )}

      {error && (
        <div className="bg-red-50 border border-red-200 rounded-xl p-4 flex items-start gap-3">
          <AlertTriangle className="h-5 w-5 text-red-500 mt-0.5" />
          <div>
            <p className="text-sm font-medium text-red-900">Failed to load templates</p>
            <p className="text-sm text-red-700 mt-1">{error}</p>
          </div>
        </div>
      )}

      {!loading && ekuUnverified && (
        <div className="bg-amber-50 border border-amber-200 rounded-xl p-4 flex items-start gap-3">
          <ShieldAlert className="h-5 w-5 text-amber-600 mt-0.5" />
          <div>
            <p className="text-sm font-semibold text-amber-900">EKU could not be verified</p>
            <p className="text-sm text-amber-700 mt-1">
              This host may not be domain joined, or the service account cannot read the
              AD Configuration partition. Showing all templates. Confirm your choice
              issues server authentication certificates.
            </p>
          </div>
        </div>
      )}

      {!loading && templates.length > 0 && (
        <div className="space-y-2">
          {templates.map((template) => {
            const isSelected = selected === template.name;
            return (
              <div key={template.name}>
                <label
                  className={`flex items-center gap-3 p-3 rounded-xl border cursor-pointer transition-colors ${
                    isSelected
                      ? 'border-certus-300 bg-certus-50'
                      : 'border-slate-200 bg-white hover:border-slate-300'
                  }`}
                >
                  <input
                    type="radio"
                    name="template"
                    checked={isSelected}
                    onChange={() => selectTemplate(template)}
                    className="h-4 w-4 text-certus-600 border-slate-300 focus:ring-certus-500"
                  />
                  <FileCheck2 className={`h-4 w-4 ${isSelected ? 'text-certus-600' : 'text-slate-400'}`} />
                  <div className="flex-1 min-w-0">
                    <div className="text-sm font-medium text-slate-900">{template.displayName || template.name}</div>
                    <div className="text-xs text-slate-500">
                      Name: <code className="bg-slate-100 px-1 rounded">{template.name}</code>
                      {template.oid && <span className="ml-2">OID: {template.oid}</span>}
                    </div>
                  </div>
                  {isSelected && (
                    <div className="text-xs text-certus-700 whitespace-nowrap">
                      /acme/{template.name}/directory
                    </div>
                  )}
                </label>
                {isSelected && <AcmeViabilityChecklist template={template} />}
              </div>
            );
          })}
        </div>
      )}

      {!loading && !error && templates.length > 0 && excludedCount > 0 && (
        <div className="flex items-start gap-2 text-xs text-slate-500">
          <Info className="h-4 w-4 text-slate-400 mt-0.5 shrink-0" />
          <p>
            {excludedCount} {excludedCount === 1 ? 'template' : 'templates'} on this CA{' '}
            {excludedCount === 1 ? 'was' : 'were'} hidden. Each either lacks the Server
            Authentication usage, has a subject built from Active Directory instead of
            the request, or could not be checked (its AD object could not be read, even
            though other templates on this CA resolved fine).
          </p>
        </div>
      )}

      {!loading && templates.length === 0 && !error && (
        <div className="text-center py-12 text-slate-400">
          <FileCheck2 className="h-8 w-8 mx-auto mb-2" />
          {excludedCount > 0 ? (
            <p className="text-sm">
              All {excludedCount} published templates were hidden: none could be confirmed
              to issue ACME server certificates. A usable template needs the Server
              Authentication usage and "Supply in the request" on its Subject Name tab;
              a template could also be hidden because its AD object could not be read.
            </p>
          ) : (
            <p className="text-sm">No server authentication templates found on the CA.</p>
          )}
        </div>
      )}
    </div>
  );
}

type CheckStatus = 'pass' | 'warn' | 'unverified' | 'info';

interface CheckItem {
  status: CheckStatus;
  label: string;
  detail?: string;
}

/**
 * The ACME viability checklist for the selected template, built from the
 * template's AD attributes. Advisory only: a warning names the exact ADCS
 * fix but never blocks the wizard. Enrolling the server's own certificate
 * at the External URL step is the live end to end test on top of these
 * static checks.
 */
function AcmeViabilityChecklist({ template }: { template: SetupTemplate }) {
  const v = template.viability;

  const items: CheckItem[] = [
    template.ekuVerified
      ? { status: 'pass', label: 'Issues server authentication certificates' }
      : {
          status: 'unverified',
          label: 'Issues server authentication certificates',
          detail: 'The EKU set could not be read from AD.',
        },
    v?.requiresManagerApproval == null
      ? {
          status: 'unverified',
          label: 'No CA manager approval required',
          detail: 'The issuance requirements could not be read from AD.',
        }
      : v.requiresManagerApproval
        ? {
            status: 'warn',
            label: 'CA manager approval is required',
            detail:
              'Every ACME request will wait for manual approval on the CA. Uncheck ' +
              '"CA certificate manager approval" on the Issuance Requirements tab of this template.',
          }
        : { status: 'pass', label: 'No CA manager approval required' },
    v?.requiresRaSignatures == null
      ? {
          status: 'unverified',
          label: 'No enrollment agent signatures required',
          detail: 'The signature requirements could not be read from AD.',
        }
      : v.requiresRaSignatures
        ? {
            status: 'warn',
            label: 'Enrollment agent signatures are required',
            detail:
              'ACME requests never carry agent signatures, so the CA will deny every one. Set ' +
              '"This number of authorized signatures" to 0 on the Issuance Requirements tab.',
          }
        : { status: 'pass', label: 'No enrollment agent signatures required' },
    v?.subjectSuppliedInRequest == null
      ? {
          status: 'unverified',
          label: 'Subject and SAN are taken from the request',
          detail: 'The subject name source could not be read from AD.',
        }
      : v.subjectSuppliedInRequest
        ? { status: 'pass', label: 'Subject and SAN are taken from the request' }
        : {
            status: 'warn',
            label: 'Subject is built from Active Directory',
            detail:
              'The CA will ignore the names ACME clients request and stamp the service account’s ' +
              'identity on every certificate. Select "Supply in the request" on the Subject Name ' +
              'tab of this template.',
          },
    v?.keyAlgorithm
      ? {
          status: 'info',
          label: `Requires ${v.keyAlgorithm} keys${
            v.minimalKeySize ? `, minimum ${v.minimalKeySize} bits` : ''
          }`,
          detail: 'ACME clients must request a matching key type or the CA denies the request.',
        }
      : {
          status: 'unverified',
          label: 'Key algorithm and size',
          detail: 'The key requirements could not be read from AD.',
        },
  ];

  const hasWarnings = items.some((i) => i.status === 'warn');

  return (
    <div className="mt-2 ml-4 border border-slate-200 rounded-xl bg-white p-3 space-y-2">
      <p className="text-xs font-semibold text-slate-700">ACME readiness</p>
      <ul className="space-y-1.5">
        {items.map((item) => (
          <li key={item.label} className="flex items-start gap-2">
            {item.status === 'pass' && <CheckCircle2 className="h-4 w-4 text-emerald-500 mt-0.5 shrink-0" />}
            {item.status === 'warn' && <AlertTriangle className="h-4 w-4 text-amber-500 mt-0.5 shrink-0" />}
            {item.status === 'info' && <Info className="h-4 w-4 text-slate-400 mt-0.5 shrink-0" />}
            {item.status === 'unverified' && <HelpCircle className="h-4 w-4 text-slate-300 mt-0.5 shrink-0" />}
            <div>
              <p className={`text-xs font-medium ${
                item.status === 'warn' ? 'text-amber-900' : 'text-slate-700'
              }`}>
                {item.label}
              </p>
              {item.detail && (
                <p className={`text-xs ${
                  item.status === 'warn' ? 'text-amber-700' : 'text-slate-500'
                }`}>
                  {item.detail}
                </p>
              )}
            </div>
          </li>
        ))}
      </ul>
      {hasWarnings && (
        <p className="text-xs text-amber-800 border-t border-slate-100 pt-2">
          These checks are advisory and you can continue, but ACME issuance will fail or stall
          until the flagged settings are changed in the Certificate Templates console.
        </p>
      )}
    </div>
  );
}
