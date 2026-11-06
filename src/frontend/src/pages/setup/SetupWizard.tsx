import { useState, useEffect } from 'react';
import { useNavigate } from 'react-router';
import { useQueryClient } from '@tanstack/react-query';
import { ChevronRight, ChevronLeft, Check, ExternalLink, Loader2 } from 'lucide-react';
import { DuckMark } from '@/features/dashboard/components/DuckMark';
import { SupportFooter } from '@/components/SupportFooter';
import { ThemeToggle } from '@/components/ThemeToggle';
import { WelcomeStep } from './WelcomeStep';
import { ConnectionStep } from './ConnectionStep';
import { TemplatesStep } from './TemplatesStep';
import { AllowedDomainsStep } from './AllowedDomainsStep';
import { ExternalUrlStep } from './ExternalUrlStep';
import { ReviewStep } from './ReviewStep';
import {
  fetchSetupConfig,
  fetchSetupStatus,
  fetchSetupTemplates,
  saveWizardDraft,
  testCaConnection,
} from '@/api/setup';
import {
  initialDomainPosture,
  initialEabEnforcement,
  isPastStep,
  recordedEabEnforcement,
  recordedTemplates,
  resumeStepIndex,
  wizardSteps,
  type EabModeName,
  type InstanceModeName,
} from '@/lib/setupWizard';

export interface WizardState {
  /**
   * The instance mode the server reported (issue #471). Monitor mode skips the
   * Templates and Client Access steps, records no template, and offers a
   * certificate from the machine store instead of enrolling one.
   */
  mode: InstanceModeName;
  /**
   * A server that finished setup in monitor mode was switched to full, so the
   * wizard reopened at the Templates step (issue #471).
   */
  reopenedForIssuance: boolean;
  caConnectionString: string;
  caName: string;
  caDnsName: string;
  connectionTested: boolean;
  selectedTemplates: string[];
  /**
   * The domain restriction choice from the Client Access step. On a
   * domain joined machine the wizard defaults to restricted with the AD
   * domain prefilled (the secure default for new installs); in a workgroup
   * it defaults to off with an empty list.
   */
  allowedDomainsEnabled: boolean;
  allowedDomains: string[];
  /** The machine's AD domain, or null in a workgroup. Suggestion only. */
  adDomainSuggestion: string | null;
  /**
   * The external account binding choice from the Client Access step (issue
   * #631): required on a fresh install, whatever the file records otherwise.
   */
  eabEnforcement: EabModeName;
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
  /**
   * The External URL step's TLS enrollment is mid flight (enrolling, the
   * mid wizard restart, or the revalidation after it). Every fetch from
   * this page fails during that window, so the shell locks Back and Next
   * rather than letting a click land on a step that cannot load.
   */
  urlStepBusy: boolean;
  /**
   * Set when the enrolled certificate does not cover the host this page is
   * on: after the restart this origin never answers TLS for this browser
   * again, so no step here can fetch anything. The only way forward is a
   * whole page navigation to this URL (the CSP's connect-src 'self' forbids
   * fetching the new origin from here). The shell turns Next into that
   * navigation and keeps Back locked.
   */
  continueElsewhereUrl: string | null;
  /**
   * Whether the continue link's unlock countdown has finished. Until then
   * the restart is assumed still in progress and the continue affordances
   * stay disabled, because a readiness probe is impossible cross origin.
   */
  continueUnlocked: boolean;
  /**
   * The Review step is submitting completion or showing a post completion
   * phase. Back is locked then: during the completion restart a previous
   * step could not load, and after completion the wizard endpoints are
   * locked anyway.
   */
  reviewBusy: boolean;
}

const initialState: WizardState = {
  mode: 'full',
  reopenedForIssuance: false,
  caConnectionString: '',
  caName: '',
  caDnsName: '',
  connectionTested: false,
  selectedTemplates: [],
  allowedDomainsEnabled: false,
  allowedDomains: [],
  adDomainSuggestion: null,
  eabEnforcement: 'required',
  externalUrl: '',
  urlValidated: false,
  urlConfirmedDespiteUnreachable: false,
  templateKeyAlgorithm: null,
  templateMinimalKeySize: null,
  tlsCertificateThumbprint: null,
  tlsCertificateInstalled: false,
  urlStepBusy: false,
  continueElsewhereUrl: null,
  continueUnlocked: false,
  reviewBusy: false,
};

/**
 * The host to name on the continue button. The URL is server built and
 * should always parse, but a throw here would take down the whole wizard
 * shell mid restart, so fall back to the raw string instead, the same
 * defensive stance ExternalUrlStep takes with its URL previews.
 */
function continueHost(url: string): string {
  try {
    return new URL(url).host;
  } catch {
    return url;
  }
}

export function SetupWizard() {
  const navigate = useNavigate();
  const queryClient = useQueryClient();
  const [currentStep, setCurrentStep] = useState(0);
  const [state, setState] = useState<WizardState>(initialState);
  const [checking, setChecking] = useState(true);
  // The steps for the mode the server reported; monitor mode skips two of them.
  const steps = wizardSteps(state.mode);

  // RequireSetup caches the status; without invalidation its stale
  // "not completed" answer bounces the finished wizard straight back here.
  // The Review step can send the administrator straight to the alert
  // settings instead of the dashboard (issue #471).
  const finishToDashboard = async (path = '/') => {
    await queryClient.invalidateQueries({ queryKey: ['setup-status'] });
    await queryClient.invalidateQueries({ queryKey: ['setup-config'] });
    navigate(path);
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
          const mode: InstanceModeName = config.mode === 'monitor' ? 'monitor' : 'full';
          const modeSteps = wizardSteps(mode);
          const caConnectionString = config.caConnectionString ?? '';
          // Monitor mode records no template, so a template left in the file
          // (an install switched from full) is not carried into its drafts.
          const selectedTemplates = recordedTemplates(mode, config.enabledTemplates);
          const suggestedDomain = config.suggestedAllowedDomain ?? null;
          const domainPosture = initialDomainPosture({
            mode,
            wizardStep: config.wizardStep,
            allowedDomainsEnabled: config.allowedDomainsEnabled,
            allowedDomains: config.allowedDomains,
            suggestedDomain,
          });
          setState((prev) => ({
            ...prev,
            mode,
            reopenedForIssuance: config.reopenReason === 'issuanceEnabled',
            caConnectionString: caConnectionString || prev.caConnectionString,
            selectedTemplates:
              selectedTemplates.length > 0 ? selectedTemplates : prev.selectedTemplates,
            allowedDomainsEnabled: domainPosture.enabled,
            allowedDomains: domainPosture.domains,
            adDomainSuggestion: suggestedDomain,
            eabEnforcement: initialEabEnforcement(config.eabEnforcement),
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
          // a step whose inputs are missing. By step id, because the same
          // step sits at a different index in each mode (issue #471). A
          // reopened wizard has no template, so this is also what lands it
          // on the Templates step.
          let target = resumeStepIndex(modeSteps, {
            wizardStep: config.wizardStep,
            hasCa: caConnectionString.length > 0,
            hasTemplates: selectedTemplates.length > 0,
            hasExternalUrl: !!config.externalUrl,
          });

          if (isPastStep(modeSteps, target, 'templates') && selectedTemplates.length > 0) {
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

          const connectionIndex = modeSteps.findIndex((s) => s.id === 'connection');
          if (isPastStep(modeSteps, target, 'connection')) {
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
                target = connectionIndex;
              }
            } catch {
              target = connectionIndex;
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
      <div className="min-h-screen bg-bg flex items-center justify-center">
        <Loader2 className="h-8 w-8 text-certus-500 animate-spin" />
      </div>
    );
  }

  const canAdvance = (): boolean => {
    switch (steps[currentStep].id) {
      case 'welcome': return true;
      case 'connection': return state.connectionTested;
      case 'templates': return state.selectedTemplates.length > 0;
      case 'domains':
        return !state.allowedDomainsEnabled || state.allowedDomains.length > 0;
      case 'url':
        // urlValidated is earned before the TLS enrollment starts, so it
        // alone must not keep Next live through the mid wizard restart:
        // a click then lands on Review, where every fetch fails.
        return state.urlValidated && state.externalUrl.length > 0 && !state.urlStepBusy;
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
        enabledTemplates: recordedTemplates(state.mode, state.selectedTemplates),
        externalUrl: state.externalUrl,
        allowedDomainsEnabled: state.allowedDomainsEnabled,
        allowedDomains: state.allowedDomains,
        eabEnforcement: recordedEabEnforcement(state.mode, state.eabEnforcement),
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
    <div className="min-h-screen bg-bg">
      {/* Header — deep-slate brand chrome, matching the app shell. Driven by
          tokens rather than inline styles, which cannot respond to `.dark`. */}
      <header className="border-b text-white bg-nav-bg border-nav-border">
        <div className="max-w-3xl mx-auto px-6 py-5">
          <div className="flex items-center justify-between gap-3">
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
            {/* The wizard renders outside Layout, so without this a first run on
                a dark-preferring machine has no way to reach light mode. */}
            <ThemeToggle />
          </div>
        </div>
      </header>

      {/* Progress bar */}
      <div className="bg-surface border-b border-hairline shadow-sm">
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
                          ? 'bg-certus-100 dark:bg-certus-500/15 text-certus-700 dark:text-certus-300 border-2 border-certus-600'
                          : 'bg-sunken-strong text-faint'
                      }`}
                  >
                    {idx < currentStep ? <Check className="h-4 w-4" /> : idx + 1}
                  </div>
                  <span className={`text-sm hidden sm:inline ${
                    idx <= currentStep ? 'text-ink font-medium' : 'text-faint'
                  }`}>
                    {step.label}
                  </span>
                </div>
                {idx < steps.length - 1 && (
                  <div className={`w-12 h-0.5 mx-2 ${
                    idx < currentStep ? 'bg-certus-600' : 'bg-track'
                  }`} />
                )}
              </div>
            ))}
          </div>
        </div>
      </div>

      {/* Step content */}
      <div className="max-w-3xl mx-auto px-6 py-8">
        <div className="bg-surface rounded-2xl border border-hairline shadow-sm p-6 min-h-[400px]">
          {steps[currentStep].id === 'welcome' && <WelcomeStep monitorMode={state.mode === 'monitor'} />}
          {steps[currentStep].id === 'connection' && (
            <ConnectionStep state={state} onUpdate={updateState} />
          )}
          {steps[currentStep].id === 'templates' && (
            <TemplatesStep state={state} onUpdate={updateState} />
          )}
          {steps[currentStep].id === 'domains' && (
            <AllowedDomainsStep state={state} onUpdate={updateState} />
          )}
          {steps[currentStep].id === 'url' && (
            <ExternalUrlStep state={state} onUpdate={updateState} />
          )}
          {steps[currentStep].id === 'review' && (
            <ReviewStep state={state} onUpdate={updateState} onComplete={finishToDashboard} />
          )}
        </div>

        {/* Navigation buttons */}
        <div className="flex items-center justify-between mt-6">
          <button
            onClick={goBack}
            disabled={
              currentStep === 0 ||
              state.urlStepBusy ||
              state.continueElsewhereUrl !== null ||
              state.reviewBusy
            }
            className="inline-flex items-center gap-2 px-4 py-2 text-sm font-medium text-ink-soft
                       bg-surface border border-hairline-strong rounded-lg hover:bg-sunken
                       disabled:opacity-50 disabled:cursor-not-allowed transition-colors"
          >
            <ChevronLeft className="h-4 w-4" />
            Back
          </button>

          {currentStep < steps.length - 1 &&
            (steps[currentStep].id === 'url' && state.continueElsewhereUrl !== null ? (
              // The old origin stops answering after the restart, so Next
              // can never work again from this page. Give the instinctive
              // bottom right click the same destination as the panel link:
              // a whole page navigation to the covered origin, held back
              // until the unlock countdown says the restart had its time.
              <button
                onClick={() => window.location.assign(state.continueElsewhereUrl!)}
                disabled={!state.continueUnlocked}
                className="inline-flex items-center gap-2 px-4 py-2 text-sm font-medium text-white
                           bg-certus-600 rounded-lg hover:bg-certus-700
                           disabled:opacity-50 disabled:cursor-not-allowed transition-colors"
              >
                Continue at {continueHost(state.continueElsewhereUrl)}
                <ExternalLink className="h-4 w-4" />
              </button>
            ) : (
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
            ))}
        </div>
      </div>

      {/* The wizard renders outside Layout, so it needs its own mount. An
          operator who gives up here is the one no other channel will ever hear
          from, which makes this the most valuable place the link appears. */}
      <SupportFooter containerClassName="max-w-3xl mx-auto px-6" />
    </div>
  );
}
