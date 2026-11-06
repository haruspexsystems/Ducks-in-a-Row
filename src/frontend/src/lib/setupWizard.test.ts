import { describe, it, expect } from 'vitest';
import {
  initialDomainPosture,
  initialEabEnforcement,
  isPastStep,
  recordedEabEnforcement,
  recordedTemplates,
  resumeStepIndex,
  wizardSteps,
  type ResumeFacts,
} from './setupWizard';

const everything: Omit<ResumeFacts, 'wizardStep'> = {
  hasCa: true,
  hasTemplates: true,
  hasExternalUrl: true,
};

/** The step id the resumed index points at, which is what the tests care about. */
function resumeAt(mode: 'full' | 'monitor', facts: ResumeFacts): string {
  const steps = wizardSteps(mode);
  return steps[resumeStepIndex(steps, facts)].id;
}

/**
 * The wizard's shape in each instance mode (issue #471). Monitor mode never
 * issues, so it skips two steps, and a draft saved in one shape must still
 * resume sensibly.
 */
describe('wizardSteps', () => {
  it('walks every step in full mode, in order', () => {
    expect(wizardSteps('full').map((s) => s.id)).toEqual([
      'welcome', 'connection', 'templates', 'domains', 'url', 'review',
    ]);
  });

  it('skips Templates and Client Access in monitor mode', () => {
    expect(wizardSteps('monitor').map((s) => s.id)).toEqual([
      'welcome', 'connection', 'url', 'review',
    ]);
  });
});

describe('resumeStepIndex', () => {
  it('resumes at the drafted step when everything it needs is there', () => {
    expect(resumeAt('monitor', { ...everything, wizardStep: 'review' })).toBe('review');
    expect(resumeAt('full', { ...everything, wizardStep: 'domains' })).toBe('domains');
  });

  it('maps a step monitor mode skips forward to the next one it has', () => {
    expect(resumeAt('monitor', { ...everything, wizardStep: 'domains' })).toBe('url');
    expect(resumeAt('monitor', { ...everything, wizardStep: 'templates' })).toBe('url');
  });

  it('sends a draft with no CA back to the connection step', () => {
    expect(resumeAt('full', { ...everything, hasCa: false, wizardStep: 'review' })).toBe('connection');
    expect(resumeAt('monitor', { ...everything, hasCa: false, wizardStep: 'review' })).toBe('connection');
  });

  it('sends a full mode draft with no template back to Templates, which is how a reopened wizard lands', () => {
    expect(resumeAt('full', { ...everything, hasTemplates: false, wizardStep: 'templates' })).toBe('templates');
    expect(resumeAt('full', { ...everything, hasTemplates: false, wizardStep: 'review' })).toBe('templates');
  });

  it('never clamps a monitor mode draft for having no template', () => {
    expect(resumeAt('monitor', { ...everything, hasTemplates: false, wizardStep: 'review' })).toBe('review');
  });

  it('sends a draft with no URL back to the External URL step', () => {
    expect(resumeAt('full', { ...everything, hasExternalUrl: false, wizardStep: 'review' })).toBe('url');
    expect(resumeAt('monitor', { ...everything, hasExternalUrl: false, wizardStep: 'review' })).toBe('url');
  });

  it('starts at Welcome for a missing or unknown step', () => {
    expect(resumeAt('full', { ...everything, wizardStep: null })).toBe('welcome');
    expect(resumeAt('monitor', { ...everything, wizardStep: 'somewhere' })).toBe('welcome');
  });
});

describe('isPastStep', () => {
  it('answers by id, and false for a step the mode does not have', () => {
    const full = wizardSteps('full');
    expect(isPastStep(full, 3, 'templates')).toBe(true);
    expect(isPastStep(full, 2, 'templates')).toBe(false);
    expect(isPastStep(wizardSteps('monitor'), 3, 'templates')).toBe(false);
  });
});

describe('recordedTemplates', () => {
  it('records the selection in full mode and nothing in monitor mode', () => {
    expect(recordedTemplates('full', ['WebServer'])).toEqual(['WebServer']);
    // The server refuses a template in monitor mode, so a stale selection must
    // never reach a draft or the completion request.
    expect(recordedTemplates('monitor', ['WebServer'])).toEqual([]);
  });
});

const freshFacts = {
  mode: 'full' as const,
  wizardStep: null,
  allowedDomainsEnabled: false,
  allowedDomains: [] as string[],
  suggestedDomain: 'corp.example.com',
};

/**
 * The domain restriction the wizard starts with: on with the Active Directory
 * domain on a domain joined server, the secure default for a new install
 * (issue #631 confirms it); off in a workgroup and in monitor mode.
 */
describe('initialDomainPosture', () => {
  it('restricts a fresh domain joined install to its AD domain', () => {
    expect(initialDomainPosture(freshFacts)).toEqual({ enabled: true, domains: ['corp.example.com'] });
  });

  it('leaves a workgroup install unrestricted, with nothing to suggest', () => {
    expect(initialDomainPosture({ ...freshFacts, suggestedDomain: null }))
      .toEqual({ enabled: false, domains: [] });
  });

  it('restricts nothing in monitor mode, which issues nothing', () => {
    expect(initialDomainPosture({ ...freshFacts, mode: 'monitor' })).toEqual({ enabled: false, domains: [] });
  });

  it('keeps an explicit off once the draft is past the domain step', () => {
    expect(initialDomainPosture({ ...freshFacts, wizardStep: 'url' })).toEqual({ enabled: false, domains: [] });
    expect(initialDomainPosture({ ...freshFacts, wizardStep: 'review' })).toEqual({ enabled: false, domains: [] });
  });

  it('keeps a positive choice the file already carries', () => {
    expect(initialDomainPosture({
      ...freshFacts,
      allowedDomainsEnabled: true,
      allowedDomains: ['example.net'],
    })).toEqual({ enabled: true, domains: ['example.net'] });
  });
});

/**
 * The binding mode the wizard starts with (issue #631): required on a fresh
 * install, which the server reports as null, and whatever the file records
 * otherwise, so an upgraded install keeps off.
 */
describe('initialEabEnforcement', () => {
  it('offers binding required when the server sent no mode', () => {
    expect(initialEabEnforcement(null)).toBe('required');
    expect(initialEabEnforcement(undefined)).toBe('required');
  });

  it('keeps what the file records', () => {
    expect(initialEabEnforcement('off')).toBe('off');
    expect(initialEabEnforcement('optional')).toBe('optional');
    expect(initialEabEnforcement('Required')).toBe('required');
  });

  it('reads a value the policy would not recognise as off, as the policy does', () => {
    expect(initialEabEnforcement('sometimes')).toBe('off');
  });
});

describe('recordedEabEnforcement', () => {
  it('sends the choice in full mode and nothing in monitor mode', () => {
    expect(recordedEabEnforcement('full', 'off')).toBe('off');
    expect(recordedEabEnforcement('full', 'required')).toBe('required');
    // Monitor mode does not ask, so the server records its own default.
    expect(recordedEabEnforcement('monitor', 'off')).toBeUndefined();
  });
});
