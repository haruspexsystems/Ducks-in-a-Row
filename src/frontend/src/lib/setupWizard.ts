/**
 * The setup wizard's shape, as pure functions so the parts that differ between
 * the two instance modes can be tested without a browser (issue #471).
 *
 * In monitor mode the service never issues, so the Templates and Client Access
 * steps are skipped. That is also why the resume logic works on step ids rather
 * than positions: the same draft step lands on a different index in each mode.
 */

/** The instance mode as the API reports it. */
export type InstanceModeName = 'full' | 'monitor';

export type WizardStepId = 'welcome' | 'connection' | 'templates' | 'domains' | 'url' | 'review';

export interface WizardStep {
  id: WizardStepId;
  label: string;
}

/** Every step, in the order a full mode wizard walks them. */
export const ALL_STEPS: readonly WizardStep[] = [
  { id: 'welcome', label: 'Welcome' },
  { id: 'connection', label: 'CA Connection' },
  { id: 'templates', label: 'Templates' },
  { id: 'domains', label: 'Client Access' },
  { id: 'url', label: 'External URL' },
  { id: 'review', label: 'Review' },
];

/** The steps for a mode. Monitor mode has no template to pick and no domain to restrict. */
export function wizardSteps(mode: InstanceModeName): WizardStep[] {
  return mode === 'monitor'
    ? ALL_STEPS.filter((step) => step.id !== 'templates' && step.id !== 'domains')
    : [...ALL_STEPS];
}

/** What the prefilled state can support, for clamping a resumed step. */
export interface ResumeFacts {
  /** The step id the draft recorded, if any. */
  wizardStep: string | null | undefined;
  hasCa: boolean;
  hasTemplates: boolean;
  hasExternalUrl: boolean;
}

/**
 * The index in <code>steps</code> to resume at. A step the draft names that this
 * mode skips maps forward to the next step that exists, so a draft saved at
 * "domains" resumes at "url" in monitor mode. The clamps then go by id, so a
 * hand edited or stale draft cannot land past a step whose input is missing: no
 * CA sends it back to Connection, no template to Templates (a step monitor mode
 * does not have, so that clamp never applies there), and no URL to External URL.
 * An unknown step starts at Welcome.
 */
export function resumeStepIndex(steps: readonly WizardStep[], facts: ResumeFacts): number {
  const canonical = ALL_STEPS.findIndex((step) => step.id === facts.wizardStep);
  if (canonical < 0) return 0;

  let target = steps.findIndex(
    (step) => ALL_STEPS.findIndex((c) => c.id === step.id) >= canonical,
  );
  if (target < 0) target = steps.length - 1;

  const clampTo = (id: WizardStepId) => {
    const index = steps.findIndex((step) => step.id === id);
    if (index >= 0 && target > index) target = index;
  };
  if (!facts.hasCa) clampTo('connection');
  if (!facts.hasTemplates) clampTo('templates');
  if (!facts.hasExternalUrl) clampTo('url');

  return target;
}

/** Whether <code>index</code> lies past the step with <code>id</code>, which must exist. */
export function isPastStep(steps: readonly WizardStep[], index: number, id: WizardStepId): boolean {
  const stepIndex = steps.findIndex((step) => step.id === id);
  return stepIndex >= 0 && index > stepIndex;
}

/**
 * The templates the wizard records, in a draft or at completion. Monitor mode
 * records none, and the server refuses any: a template recorded there would go
 * live for ACME the moment the server is switched to full.
 */
export function recordedTemplates(mode: InstanceModeName, selected: readonly string[]): string[] {
  return mode === 'monitor' ? [] : [...selected];
}

/** The domain restriction the wizard starts with. */
export interface DomainPosture {
  enabled: boolean;
  domains: string[];
}

/** What the server reported that decides the starting domain restriction. */
export interface DomainPostureFacts {
  mode: InstanceModeName;
  /** The step a saved draft recorded, if any. */
  wizardStep: string | null | undefined;
  allowedDomainsEnabled: boolean | undefined;
  allowedDomains: string[] | undefined;
  /** The machine's Active Directory domain, or null in a workgroup. */
  suggestedDomain: string | null;
}

/**
 * The domain restriction the wizard starts with. The file's choice is
 * authoritative in two cases: the draft was saved at or past the External URL
 * step (the wizard drafts the step being entered, so the administrator has
 * been through the domain step, and an explicit off with an emptied list must
 * survive the mid wizard TLS restart), or the file carries a positive choice (a
 * stranded install keeping its old policy). Otherwise the default posture
 * applies: restricted to the Active Directory domain on a domain joined
 * server, unrestricted in a workgroup, where there is nothing to suggest.
 * Monitor mode issues nothing, so it has no domain to restrict.
 */
export function initialDomainPosture(facts: DomainPostureFacts): DomainPosture {
  if (facts.mode === 'monitor') return { enabled: false, domains: [] };

  const draftPassedDomainsStep = facts.wizardStep === 'url' || facts.wizardStep === 'review';
  const fileHasDomainChoice =
    (facts.allowedDomainsEnabled ?? false) || (facts.allowedDomains ?? []).length > 0;
  if (draftPassedDomainsStep || fileHasDomainChoice) {
    return { enabled: facts.allowedDomainsEnabled ?? false, domains: facts.allowedDomains ?? [] };
  }

  return facts.suggestedDomain !== null
    ? { enabled: true, domains: [facts.suggestedDomain] }
    : { enabled: false, domains: [] };
}

/** An external account binding mode, as the server names it. */
export type EabModeName = 'off' | 'optional' | 'required';

/**
 * The binding mode the wizard starts with (issue #631). The server decides it:
 * the recorded mode, "off" for an install upgraded from before the setting
 * existed, and required on a fresh install, so binding is on by default and
 * switching it off is an explicit choice. Only a response without the field
 * falls back to required here. A value the policy would not recognise (a hand
 * edit) reads as off, which is how the enforcement policy reads it too.
 */
export function initialEabEnforcement(recorded: string | null | undefined): EabModeName {
  if (recorded === null || recorded === undefined) return 'required';
  const mode = recorded.trim().toLowerCase();
  return mode === 'optional' || mode === 'required' || mode === 'off' ? mode : 'off';
}

/**
 * The binding choice the wizard sends, in a draft or at completion. Monitor
 * mode issues nothing, so the wizard does not ask and sends nothing: the
 * server then keeps what the file records or, on a fresh install, records
 * required, so a server later switched to full starts with binding on.
 */
export function recordedEabEnforcement(
  mode: InstanceModeName,
  chosen: EabModeName,
): EabModeName | undefined {
  return mode === 'monitor' ? undefined : chosen;
}
