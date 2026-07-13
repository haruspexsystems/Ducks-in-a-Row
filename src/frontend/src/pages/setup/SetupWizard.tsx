import { useState, useEffect } from 'react';
import { useNavigate } from 'react-router-dom';
import { useQueryClient } from '@tanstack/react-query';
import { ChevronRight, ChevronLeft, Check, Loader2 } from 'lucide-react';
import { DuckMark } from '@/features/dashboard/components/DuckMark';
import { NAV_BG, NAV_BORDER } from '@/features/dashboard/lib/colors';
import { WelcomeStep } from './WelcomeStep';
import { ConnectionStep } from './ConnectionStep';
import { TemplatesStep } from './TemplatesStep';
import { ExternalUrlStep } from './ExternalUrlStep';
import { ReviewStep } from './ReviewStep';
import {
  fetchSetupConfig,
  fetchSetupStatus,
  fetchSetupTemplates,
  saveWizardDraft,
  testCaConnection,
} from '@/api/setup';

export interface WizardState {
  caConnectionString: string;
  caName: string;
  caDnsName: string;
  connectionTested: boolean;
  selectedTemplates: string[];
  externalUrl: string;
  urlValidated: boolean;
  /**
   * The reachability probe failed and the admin explicitly chose to keep
   * the URL (reverse proxy or hairpin NAT deployments). Carried through to
   * completion so the repeat probe there does not refuse the request.
   */
  urlConfirmedDespiteUnreachable: boolean;
  /**
   * Key requirements of the selected template, read from AD at the Templates
   * step. Null when they could not be verified; the review page then shows
   * its generic RSA note instead of a data driven one.
   */
  templateKeyAlgorithm: string | null;
  templateMinimalKeySize: number | null;
  /**
   * The TLS certificate the settings overlay already points at, from a
   * wizard TLS enrollment that happened before this page load. The External
   * URL step uses it to show "installed" instead of offering to enroll
   * again after the cross origin continue hop or an F5 during the restart.
   * Null when no certificate is configured, or when one is configured but
   * is no longer present in the store (tlsCertificateInstalled is false) —
   * that state gets no special treatment; the step falls back to its normal
   * probe driven flow instead of claiming a certificate that is not there.
   */
  tlsCertificateThumbprint: string | null;
  /** Whether the configured thumbprint above was actually found in the store. */
  tlsCertificateInstalled: boolean;
}

const initialState: WizardState = {
  caConnectionString: '',
  caName: '',
  caDnsName: '',
  connectionTested: false,
  selectedTemplates: [],
  externalUrl: '',
  urlValidated: false,
  urlConfirmedDespiteUnreachable: false,
  templateKeyAlgorithm: null,
  templateMinimalKeySize: null,
  tlsCertificateThumbprint: null,
  tlsCertificateInstalled: false,
};

const steps = [
  { id: 'welcome', label: 'Welcome' },
  { id: 'connection', label: 'CA Connection' },
  { id: 'templates', label: 'Templates' },
  { id: 'url', label: 'External URL' },
  { id: 'review', label: 'Review' },
];

export function SetupWizard() {
  const navigate = useNavigate();
  const queryClient = useQueryClient();
  const [currentStep, setCurrentStep] = useState(0);
  const [state, setState] = useState<WizardState>(initialState);
  const [checking, setChecking] = useState(true);

  // RequireSetup caches the status; without invalidation its stale
  // "not completed" answer bounces the finished wizard straight back here.
  const finishToDashboard = async () => {
    await queryClient.invalidateQueries({ queryKey: ['setup-status'] });
    await queryClient.invalidateQueries({ queryKey: ['setup-config'] });
    navigate('/');
  };

  // Check if setup is already complete and in effect. When it is not but the
  // wizard was walked through before (an install stranded by the old silent
  // mock fallback, or an aborted restart), prefill the saved values so the
  // admin only has to test again and apply. A draft that recorded a wizard
  // step resumes there — that is what carries the admin across the cross
  // origin continue hop after the TLS enrollment restart, where browser
  // storage cannot follow.
  useEffect(() => {
    fetchSetupStatus()
      .then(async (status) => {
        if (status.setupCompleted) {
          navigate('/', { replace: true });
          return;
        }
        try {
          const config = await fetchSetupConfig();
          const caConnectionString = config.caConnectionString ?? '';
          const selectedTemplates = config.enabledTemplates;
          setState((prev) => ({
            ...prev,
            caConnectionString: caConnectionString || prev.caConnectionString,
            selectedTemplates:
              selectedTemplates.length > 0 ? selectedTemplates : prev.selectedTemplates,
            // A previously saved URL (a draft or a stranded install) wins;
            // otherwise seed the field with the suggestion built from the
            // machine's DNS name and the actual listening port. Editable
            // either way, and validation is still required.
            externalUrl:
              config.externalUrl ?? config.suggestedExternalUrl ?? prev.externalUrl,
            tlsCertificateThumbprint: config.tlsCertificate?.thumbprint ?? null,
            tlsCertificateInstalled: config.tlsCertificate?.installed ?? false,
          }));

          // Resume at the drafted step, clamped to what the prefilled data
          // actually supports so a hand edited or stale draft cannot land on
          // a step whose inputs are missing.
          let target = config.wizardStep
            ? steps.findIndex((s) => s.id === config.wizardStep)
            : -1;
          if (target > 1 && !caConnectionString) target = 1;
          if (target > 2 && selectedTemplates.length === 0) target = 2;
          if (target > 3 && !config.externalUrl) target = 3;

          if (target > 2 && selectedTemplates.length > 0) {
            // Resuming past the Templates step means it never mounts, so its
            // effect that reads the selected template's key requirements
            // from AD never runs. Without this, the Review step's certbot
            // guidance would silently fall back to the generic RSA
            // assumption after a reload, even for a template that actually
            // requires ECDSA. Fetch the same list TemplatesStep would and
            // pull the requirements for the template that is already
            // selected; best effort, since the guidance is advisory.
            try {
              const { templates } = await fetchSetupTemplates(caConnectionString);
              const selected = templates.find((t) => t.name === selectedTemplates[0]);
              if (selected) {
                setState((prev) => ({
                  ...prev,
                  templateKeyAlgorithm: selected.viability?.keyAlgorithm ?? null,
                  templateMinimalKeySize: selected.viability?.minimalKeySize ?? null,
                }));
              }
            } catch {
              // Best effort: the review page falls back to generic guidance.
            }
          }

          if (target > 1) {
            // Past the connection step the wizard shows the CA as tested.
            // Rerun the test honestly rather than faking a pass; a CA that
            // stopped answering sends the admin back to the connection step.
            try {
              const test = await testCaConnection(caConnectionString);
              if (test.success) {
                setState((prev) => ({
                  ...prev,
                  connectionTested: true,
                  caName: test.caName ?? '',
                  caDnsName: test.caDnsName ?? '',
                }));
              } else {
                target = 1;
              }
            } catch {
              target = 1;
            }
          }

          if (target > 0) {
            setCurrentStep(target);
          }
        } catch {
          // Config is admin only; without it the wizard just starts clean.
        }
      })
      .catch(() => {})
      .finally(() => setChecking(false));
  }, [navigate]);

  if (checking) {
    return (
      <div className="min-h-screen bg-[#F6F7F9] flex items-center justify-center">
        <Loader2 className="h-8 w-8 text-certus-500 animate-spin" />
      </div>
    );
  }

  const canAdvance = (): boolean => {
    switch (steps[currentStep].id) {
      case 'welcome': return true;
      case 'connection': return state.connectionTested;
      case 'templates': return state.selectedTemplates.length > 0;
      case 'url': return state.urlValidated && state.externalUrl.length > 0;
      case 'review': return true;
      default: return false;
    }
  };

  const goNext = () => {
    if (currentStep < steps.length - 1 && canAdvance()) {
      // Draft the state with the step being entered, so a plain reload (or
      // the restart the TLS enrollment schedules) resumes there. Fire and
      // forget: drafting must never block navigation.
      saveWizardDraft({
        caConnectionString: state.caConnectionString,
        enabledTemplates: state.selectedTemplates,
        externalUrl: state.externalUrl,
        wizardStep: steps[currentStep + 1].id,
      }).catch(() => {});
      setCurrentStep((s) => s + 1);
    }
  };

  const goBack = () => {
    if (currentStep > 0) {
      setCurrentStep((s) => s - 1);
    }
  };

  const updateState = (updates: Partial<WizardState>) => {
    setState((prev) => ({ ...prev, ...updates }));
  };

  return (
    <div className="min-h-screen bg-[#F6F7F9]">
      {/* Header — deep-slate brand chrome, matching the app shell */}
      <header className="border-b text-white" style={{ background: NAV_BG, borderColor: NAV_BORDER }}>
        <div className="max-w-3xl mx-auto px-6 py-5">
          <div className="flex items-center gap-[11px]">
            <div
              className="grid h-10 w-10 place-items-center rounded-[11px]"
              style={{ background: 'rgba(255,255,255,0.06)', boxShadow: 'inset 0 0 0 1px rgba(255,255,255,.07)' }}
            >
              <DuckMark size={30} />
            </div>
            <div className="leading-none">
              <div className="text-[18px] font-extrabold tracking-[-0.4px] text-white">Ducks in a Row Setup</div>
              <div className="mt-[3px] text-[10.5px] font-semibold tracking-[0.3px]" style={{ color: '#7C8AA3' }}>
                CERTIFICATE LIFECYCLE
              </div>
            </div>
          </div>
        </div>
      </header>

      {/* Progress bar */}
      <div className="bg-white border-b border-slate-200 shadow-sm">
        <div className="max-w-3xl mx-auto px-6 py-4">
          <div className="flex items-center justify-between">
            {steps.map((step, idx) => (
              <div key={step.id} className="flex items-center">
                <div className="flex items-center gap-2">
                  <div
                    className={`w-8 h-8 rounded-full flex items-center justify-center text-sm font-semibold
                      ${idx < currentStep
                        ? 'bg-certus-600 text-white'
                        : idx === currentStep
                          ? 'bg-certus-100 text-certus-700 border-2 border-certus-600'
                          : 'bg-slate-100 text-slate-400'
                      }`}
                  >
                    {idx < currentStep ? <Check className="h-4 w-4" /> : idx + 1}
                  </div>
                  <span className={`text-sm hidden sm:inline ${
                    idx <= currentStep ? 'text-slate-900 font-medium' : 'text-slate-400'
                  }`}>
                    {step.label}
                  </span>
                </div>
                {idx < steps.length - 1 && (
                  <div className={`w-12 h-0.5 mx-2 ${
                    idx < currentStep ? 'bg-certus-600' : 'bg-slate-200'
                  }`} />
                )}
              </div>
            ))}
          </div>
        </div>
      </div>

      {/* Step content */}
      <div className="max-w-3xl mx-auto px-6 py-8">
        <div className="bg-white rounded-2xl border border-slate-200 shadow-sm p-6 min-h-[400px]">
          {steps[currentStep].id === 'welcome' && <WelcomeStep />}
          {steps[currentStep].id === 'connection' && (
            <ConnectionStep state={state} onUpdate={updateState} />
          )}
          {steps[currentStep].id === 'templates' && (
            <TemplatesStep state={state} onUpdate={updateState} />
          )}
          {steps[currentStep].id === 'url' && (
            <ExternalUrlStep state={state} onUpdate={updateState} />
          )}
          {steps[currentStep].id === 'review' && (
            <ReviewStep state={state} onComplete={finishToDashboard} />
          )}
        </div>

        {/* Navigation buttons */}
        <div className="flex items-center justify-between mt-6">
          <button
            onClick={goBack}
            disabled={currentStep === 0}
            className="inline-flex items-center gap-2 px-4 py-2 text-sm font-medium text-slate-700
                       bg-white border border-slate-300 rounded-lg hover:bg-slate-50
                       disabled:opacity-50 disabled:cursor-not-allowed transition-colors"
          >
            <ChevronLeft className="h-4 w-4" />
            Back
          </button>

          {currentStep < steps.length - 1 && (
            <button
              onClick={goNext}
              disabled={!canAdvance()}
              className="inline-flex items-center gap-2 px-4 py-2 text-sm font-medium text-white
                         bg-certus-600 rounded-lg hover:bg-certus-700
                         disabled:opacity-50 disabled:cursor-not-allowed transition-colors"
            >
              Next
              <ChevronRight className="h-4 w-4" />
            </button>
          )}
        </div>
      </div>
    </div>
  );
}
