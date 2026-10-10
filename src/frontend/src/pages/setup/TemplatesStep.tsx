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
  const [unusableNameCount, setUnusableNameCount] = useState(0);
  const [loading, setLoading] = useState(true);
  const [error, setError] = useState<string | null>(null);

  useEffect(() => {
    setLoading(true);
    fetchSetupTemplates(state.caConnectionString)
      .then((data) => {
        if (data && Array.isArray(data.templates)) {
          setTemplates(data.templates);
          setExcludedCount(data.excludedCount ?? 0);
          setUnusableNameCount(data.unusableNameCount ?? 0);
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
        <h2 className="text-xl font-bold text-ink">Select a Certificate Template</h2>
        <p className="text-sm text-muted mt-1">
          Choose the ADCS template to expose via ACME. Only templates that can issue
          server authentication certificates are listed. The template gets its own
          ACME directory URL: <code className="bg-sunken-strong px-1 rounded text-xs">/acme/{'{'}<em>template</em>{'}'}/directory</code>
        </p>
      </div>

      {loading && (
        <div className="flex items-center justify-center py-12">
          <Loader2 className="h-6 w-6 text-certus-500 animate-spin" />
          <span className="text-sm text-muted ml-2">Loading templates from CA...</span>
        </div>
      )}

      {error && (
        <div className="bg-red-50 dark:bg-red-500/10 border border-red-200 dark:border-red-500/30 rounded-xl p-4 flex items-start gap-3">
          <AlertTriangle className="h-5 w-5 text-red-500 mt-0.5" />
          <div>
            <p className="text-sm font-medium text-red-900 dark:text-red-200">Failed to load templates</p>
            <p className="text-sm text-red-700 dark:text-red-300 mt-1">{error}</p>
          </div>
        </div>
      )}

      {!loading && ekuUnverified && (
        <div className="bg-amber-50 dark:bg-amber-500/10 border border-amber-200 dark:border-amber-500/30 rounded-xl p-4 flex items-start gap-3">
          <ShieldAlert className="h-5 w-5 text-amber-600 mt-0.5" />
          <div>
            <p className="text-sm font-semibold text-amber-900 dark:text-amber-200">EKU could not be verified</p>
            <p className="text-sm text-amber-700 dark:text-amber-300 mt-1">
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
                      ? 'border-certus-300 bg-certus-50 dark:bg-certus-500/10'
                      : 'border-hairline bg-surface hover:border-hairline-strong'
                  }`}
                >
                  <input
                    type="radio"
                    name="template"
                    checked={isSelected}
                    onChange={() => selectTemplate(template)}
                    className="h-4 w-4 text-certus-600 border-hairline-strong focus:ring-certus-500"
                  />
                  <FileCheck2 className={`h-4 w-4 ${isSelected ? 'text-certus-600' : 'text-faint'}`} />
                  {/* Every value on this row is text the CA authored, and a
                      bidirectional override in one of them reorders the text
                      around it, which is a row that names a different template
                      than the one it selects. <bdi> isolates each without
                      changing a character of it. The programmatic name cannot
                      carry one today, because a template whose programmatic
                      name does is never listed, and it is wrapped anyway so the
                      rule here is about where the text came from rather than
                      about which field it landed in. */}
                  <div className="flex-1 min-w-0">
                    <div className="text-sm font-medium text-ink">
                      <bdi>{template.displayName || template.name}</bdi>
                    </div>
                    <div className="text-xs text-muted">
                      Name:{' '}
                      <code className="bg-sunken-strong px-1 rounded">
                        <bdi>{template.name}</bdi>
                      </code>
                      {template.oid && (
                        <span className="ml-2">
                          OID: <bdi>{template.oid}</bdi>
                        </span>
                      )}
                    </div>
                  </div>
                  {isSelected && (
                    <div className="text-xs text-certus-700 dark:text-certus-300 whitespace-nowrap">
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
        <div className="flex items-start gap-2 text-xs text-muted">
          <Info className="h-4 w-4 text-faint mt-0.5 shrink-0" />
          <div className="space-y-1">
            <p>
              {excludedCount} {excludedCount === 1 ? 'template' : 'templates'} on this CA{' '}
              {excludedCount === 1 ? 'was' : 'were'} hidden. Each either lacks the Server
              Authentication usage, has a subject built from Active Directory instead of
              the request, carries a control or formatting character in its template name,
              or could not be checked (its AD object could not be read, even though other
              templates on this CA resolved fine).
            </p>
            <UnusableNameNote count={unusableNameCount} />
          </div>
        </div>
      )}

      {!loading && templates.length === 0 && !error && (
        <div className="text-center py-12 text-faint">
          <FileCheck2 className="h-8 w-8 mx-auto mb-2" />
          {excludedCount > 0 ? (
            <div className="space-y-2">
              <p className="text-sm">
                All {excludedCount} published templates were hidden: none could be confirmed
                to issue ACME server certificates. A usable template needs the Server
                Authentication usage and "Supply in the request" on its Subject Name tab;
                a template could also be hidden because its template name cannot reach ADCS,
                or because its AD object could not be read.
              </p>
              <div className="text-xs text-left max-w-xl mx-auto">
                <UnusableNameNote count={unusableNameCount} />
              </div>
            </div>
          ) : (
            <p className="text-sm">No server authentication templates found on the CA.</p>
          )}
        </div>
      )}
    </div>
  );
}

/**
 * The one hiding reason whose fix is not a setting. A programmatic name is
 * fixed when a template is created, so there is nothing to uncheck: the
 * template has to be duplicated under a clean name. Rendered wherever the
 * hidden count is explained, and silent when nothing was hidden for it.
 */
function UnusableNameNote({ count }: { count: number }) {
  if (count < 1) return null;

  return (
    <p>
      {count === 1 ? 'One of those was' : `${count} of those were`} hidden for a reason
      you cannot fix on the template: the template name itself carries a control, line
      separator, or formatting character. ADCS separates request attributes with
      newlines, so Ducks in a Row will not send such a name and no certificate can be
      requested against the template on any path. A template's name is fixed when it is
      created, so the fix is to duplicate the template with a clean name and publish the
      copy.
    </p>
  );
}

/** The U+XXXX form an operator can look up, matching what the service log prints. */
function formatCodePoint(codePoint: number): string {
  return `U+${codePoint.toString(16).toUpperCase().padStart(4, '0')}`;
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
          // An ECDH template still works, because a certificate request is
          // signed and so can only carry the signing key on that curve, but it
          // is recording an encryption only algorithm and that is worth
          // saying here rather than only on the Review step (issue #277).
          detail: v.keyAlgorithm.trim().toUpperCase().startsWith('ECDH')
            ? 'ACME clients must request an ECDSA key on this curve, which is what they produce ' +
              'anyway. This template records an encryption only algorithm because its Purpose is ' +
              '"Signature and encryption" on the Request Handling tab; set it to "Signature" to ' +
              'record ECDSA instead.'
            : 'ACME clients must request a matching key type or the CA denies the request.',
        }
      : {
          status: 'unverified',
          label: 'Key algorithm and size',
          detail: 'The key requirements could not be read from AD.',
        },
    // Last, next to the key requirements, because both are about what a client
    // has to be configured with rather than about what the CA will issue.
    template.displayNameWarning
      ? {
          status: 'warn',
          label: 'The display name cannot be used in the directory URL',
          detail:
            `The display name carries a ${template.displayNameWarning.kind} character ` +
            `(${formatCodePoint(template.displayNameWarning.codePoint)}) at position ` +
            `${template.displayNameWarning.position}. The server refuses a URL carrying ` +
            `one, so a client configured with the display name gets a 400. Point ACME ` +
            `clients at the programmatic name ${template.name} instead, or retype the ` +
            `Template display name on the General tab of this template. Characters like ` +
            `a soft hyphen are invisible, so the name looks correct everywhere it is shown.`,
        }
      : { status: 'pass', label: 'The display name can be used in the directory URL' },
    // Info, not warn, and only when there is something to say. The footer below
    // tells the reader that a warning means issuance will fail or stall until a
    // setting is changed, and for the OID that is false: nothing is refused and
    // no client is affected. There is no passing counterpart either, because a
    // clean OID is not a question anyone has, unlike the addressing form above.
    ...(template.oidWarning
      ? [
          {
            status: 'info' as const,
            label: 'The template OID carries a hidden character',
            detail:
              `The OID carries a ${template.oidWarning.kind} character ` +
              `(${formatCodePoint(template.oidWarning.codePoint)}) at position ` +
              `${template.oidWarning.position}. Nothing is refused: this template ` +
              `issues and is addressed exactly as any other, and the OID is shown ` +
              `here only to identify it. Such a character is invisible, so the OID ` +
              `looks correct in the Certificate Templates console too. A template ` +
              `OID is fixed when the template is created, so there is nothing to ` +
              `retype: leave it, or duplicate the template if you would rather ` +
              `the row read as it is stored.`,
          },
        ]
      : []),
  ];

  const hasWarnings = items.some((i) => i.status === 'warn');

  return (
    <div className="mt-2 ml-4 border border-hairline rounded-xl bg-surface p-3 space-y-2">
      <p className="text-xs font-semibold text-ink-soft">ACME readiness</p>
      <ul className="space-y-1.5">
        {items.map((item) => (
          <li key={item.label} className="flex items-start gap-2">
            {item.status === 'pass' && <CheckCircle2 className="h-4 w-4 text-emerald-500 mt-0.5 shrink-0" />}
            {item.status === 'warn' && <AlertTriangle className="h-4 w-4 text-amber-500 mt-0.5 shrink-0" />}
            {item.status === 'info' && <Info className="h-4 w-4 text-faint mt-0.5 shrink-0" />}
            {/* Fainter than `text-faint` as an opacity step, not a lighter slate:
                a literal slate-300 would become the brightest icon here on a
                dark page, inverting the "unverified is de-emphasised" reading. */}
            {item.status === 'unverified' && <HelpCircle className="h-4 w-4 text-faint/60 mt-0.5 shrink-0" />}
            <div>
              <p className={`text-xs font-medium ${
                item.status === 'warn' ? 'text-amber-900 dark:text-amber-200' : 'text-ink-soft'
              }`}>
                {item.label}
              </p>
              {item.detail && (
                <p className={`text-xs ${
                  item.status === 'warn' ? 'text-amber-700 dark:text-amber-300' : 'text-muted'
                }`}>
                  {item.detail}
                </p>
              )}
            </div>
          </li>
        ))}
      </ul>
      {hasWarnings && (
        <p className="text-xs text-amber-800 dark:text-amber-300 border-t border-hairline-soft pt-2">
          These checks are advisory and you can continue, but ACME issuance will fail or stall
          until the flagged settings are changed in the Certificate Templates console.
        </p>
      )}
    </div>
  );
}
