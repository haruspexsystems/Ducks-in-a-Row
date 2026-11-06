import { afterEach, describe, expect, it, vi } from 'vitest';
import type {
  LicenceDetails,
  LicenceInspectResponse,
  LicenceModule,
  LicenceStatusResponse,
  ModuleState,
  LicenceStatus,
} from '@/api/licence';
import {
  aboutTier,
  bannerFor,
  casPhrase,
  daysPhrase,
  describeCandidate,
  describeLicence,
  forestList,
  isNegativeTone,
  isoDate,
  isSetAside,
  licenceFacts,
  NOT_AFFECTED,
  reasonWords,
  tierName,
} from './licence';

// What the licence card, banner and About block say for every pair of module
// state and licence status (licence design section 13.3, issue #493).

const MODULE_STATES: ModuleState[] = [
  'NotPresent', 'Loaded', 'Failed', 'Unresponsive', 'Quarantined', 'Incompatible', 'Refused',
];

const LICENCE_STATUSES: LicenceStatus[] = [
  'None', 'StoredNotVerified', 'NotYetValid', 'Valid', 'Expiring', 'Grace', 'Lapsed', 'BindingMismatch', 'Invalid',
];

const VERIFIED: LicenceStatus[] = ['NotYetValid', 'Valid', 'Expiring', 'Grace', 'Lapsed', 'BindingMismatch'];

function licence(status: LicenceStatus | string, overrides: Partial<LicenceDetails> = {}): LicenceDetails {
  const verified = (VERIFIED as string[]).includes(status);
  return {
    status,
    reasonCode: status === 'Invalid' ? 'BadSignature' : verified ? 'None' : null,
    licenceId: verified ? 'lid-1' : null,
    tier: verified ? 'standard' : null,
    features: verified ? ['placeholder'] : [],
    maxCas: verified ? 2 : null,
    licenseeName: verified ? 'Example BV' : null,
    licenseeRef: verified ? 'REF-1' : null,
    validFrom: verified ? '2026-01-01T00:00:00+00:00' : null,
    validUntil: verified ? '2027-01-15T00:00:00+00:00' : null,
    warnFrom: verified ? '2026-12-16T00:00:00+00:00' : null,
    graceUntil: verified ? '2027-02-14T00:00:00+00:00' : null,
    daysRemaining: verified ? 10 : null,
    boundForests: verified ? ['corp.example.com'] : [],
    observedForest: 'other.example.com',
    clockAnomaly: false,
    unknownTier: false,
    isVerified: verified,
    ...overrides,
  };
}

function module(state: ModuleState | string, overrides: Partial<LicenceModule> = {}): LicenceModule {
  return {
    state,
    reason: state === 'Loaded' || state === 'NotPresent' ? null : 'what the host said',
    id: state === 'NotPresent' || state === 'Refused' ? null : 'paid',
    version: state === 'NotPresent' || state === 'Refused' ? null : '1.0.0',
    contract: state === 'Incompatible' ? { module: '2.0', core: '1.0' } : null,
    ...overrides,
  };
}

function response(
  state: ModuleState | string,
  status: LicenceStatus | string,
  stored: Partial<LicenceStatusResponse['stored']> = {},
  licenceOverrides: Partial<LicenceDetails> = {},
): LicenceStatusResponse {
  return {
    module: module(state),
    stored: { active: status !== 'None', previous: false, untrusted: false, ...stored },
    licence: licence(status, licenceOverrides),
  };
}

const EVERY_PAIR = MODULE_STATES.flatMap((state) => LICENCE_STATUSES.map((status) => [state, status] as const));

function allText(r: LicenceStatusResponse): string[] {
  const d = describeLicence(r);
  return [...d.lines, ...d.notes, bannerFor(r)?.text ?? '', aboutTier(r) ?? ''];
}

describe('every module state against every licence status', () => {
  it.each(EVERY_PAIR)('%s with %s reads sensibly', (state, status) => {
    const r = response(state, status);
    const d = describeLicence(r);

    expect(d.lines.length).toBeGreaterThan(0);
    for (const line of d.lines) expect(line.trim().length).toBeGreaterThan(0);
    if (isNegativeTone(d.tone)) expect(d.lines[d.lines.length - 1]).toBe(NOT_AFFECTED);
    expect(aboutTier(r)).toBeTruthy();

    const banner = bannerFor(r);
    if (banner) expect(banner.text.endsWith(NOT_AFFECTED)).toBe(true);
  });

  it.each(EVERY_PAIR)('%s with %s uses no dashes for punctuation and the British noun', (state, status) => {
    for (const text of allText(response(state, status))) {
      expect(text).not.toMatch(/[–—]/);
      expect(text).not.toMatch(/\blicense\b/i);
    }
  });

  it.each(EVERY_PAIR)('%s with %s shows no banner when nothing is stored', (state, status) => {
    expect(bannerFor(response(state, status, { active: false }))).toBeNull();
  });

  it.each(EVERY_PAIR)('%s with %s offers Retry exactly when the server accepts one', (state, status) => {
    expect(describeLicence(response(state, status)).canRetry).toBe(isSetAside(state));
  });
});

describe('the design section 13.3 wording', () => {
  it('free tier with no paid module', () => {
    const d = describeLicence(response('NotPresent', 'None'));
    expect(d.lines).toEqual(['Free tier. No paid module is installed.']);
    expect(d.tone).toBe('neutral');
  });

  it('a licence stored with no paid module', () => {
    expect(describeLicence(response('NotPresent', 'StoredNotVerified')).lines).toEqual([
      'A licence is stored but not checked, because the paid module is not installed. Install it to activate the licence.',
      NOT_AFFECTED,
    ]);
  });

  it('a loaded module with no licence names this server\'s forest', () => {
    expect(describeLicence(response('Loaded', 'None', { active: false })).lines).toEqual([
      'The paid module is installed. Upload your licence file to switch on paid features.',
      'This server is in other.example.com.',
    ]);
  });

  it('valid', () => {
    const d = describeLicence(response('Loaded', 'Valid'));
    expect(d.lines).toEqual(['Licensed to Example BV (REF-1). Standard, up to 2 CAs. Valid until 2027-01-15.']);
    expect(d.tone).toBe('good');
  });

  it('expiring, with the server\'s day count', () => {
    expect(describeLicence(response('Loaded', 'Expiring')).lines[0]).toBe(
      'Your licence expires on 2027-01-15, in 10 days. Upload the renewed file when it arrives.');
  });

  it('grace', () => {
    expect(describeLicence(response('Loaded', 'Grace')).lines[0]).toBe(
      'Your licence expired on 2027-01-15. Paid features switch off on 2027-02-14.');
  });

  it('lapsed, dated by the end of grace', () => {
    const d = describeLicence(response('Loaded', 'Lapsed'));
    expect(d.lines[0]).toBe('Your licence lapsed on 2027-02-14. Paid features are off.');
    expect(d.tone).toBe('grey');
  });

  it('a binding mismatch names both forests', () => {
    expect(describeLicence(response('Loaded', 'BindingMismatch')).lines[0]).toBe(
      'This licence is for corp.example.com. This server is in other.example.com. Paid features are off.');
  });

  it('a binding on a server that is not domain joined says so', () => {
    const r = response('Loaded', 'BindingMismatch', {}, { reasonCode: 'NotDomainJoined', observedForest: null });
    expect(describeLicence(r).lines[0]).toBe(
      'This licence is for corp.example.com. This server is not joined to a domain, so it is in no forest. Paid features are off.');
  });

  it('invalid, in plain words', () => {
    expect(describeLicence(response('Loaded', 'Invalid')).lines[0]).toBe(
      'This licence file cannot be used: its signature does not match, so it was changed after it was issued.');
  });

  it('not yet valid', () => {
    expect(describeLicence(response('Loaded', 'NotYetValid')).lines[0]).toBe(
      'Your licence starts on 2026-01-01. Paid features are off until then.');
  });

  it('incompatible names the module and both contracts', () => {
    expect(describeLicence(response('Incompatible', 'StoredNotVerified')).lines[0]).toBe(
      'The paid module 1.0.0 was built for contract 2.0. This release needs a module built for contract 1.0.');
  });

  it('refused by the folder gate', () => {
    expect(describeLicence(response('Refused', 'None')).lines[0]).toBe(
      'The paid module was not loaded, because non-administrators can change its folder. Repair the module installation.');
  });

  it('incompatible and refused say a restart follows the fix, since Retry is not offered', () => {
    for (const state of ['Incompatible', 'Refused'] as const) {
      expect(describeLicence(response(state, 'None')).notes.join(' ')).toContain('restart the service');
    }
  });

  it('a module set aside offers Retry, and says the stored licence waits for it', () => {
    for (const state of ['Failed', 'Unresponsive', 'Quarantined'] as const) {
      const d = describeLicence(response(state, 'StoredNotVerified'));
      expect(d.canRetry).toBe(true);
      expect(d.notes).toContain('Your licence is stored, and is checked once the paid module runs.');
      expect(d.detail).toBe('what the host said');
    }
  });

  it('a licence folder that cannot be trusted is said before anything else', () => {
    const d = describeLicence(response('Loaded', 'None', { active: false, untrusted: true }));
    expect(d.tone).toBe('red');
    expect(d.lines[0]).toContain('The licence folder cannot be trusted');
    expect(bannerFor(response('Loaded', 'None', { active: false, untrusted: true }))?.tone).toBe('red');
  });

  it('a state the page does not know still reads, and fails towards a warning', () => {
    expect(describeLicence(response('Exploded', 'None')).lines[0]).toContain('(Exploded)');
    expect(describeLicence(response('Loaded', 'Mystery')).lines[0]).toContain('(Mystery)');
  });
});

describe('notes', () => {
  it('warns of a clock that looks wrong', () => {
    const d = describeLicence(response('Loaded', 'Valid', {}, { clockAnomaly: true }));
    expect(d.notes.join(' ')).toContain("This server's clock looks wrong");
  });

  it('explains an unknown tier on the card, and never raises a banner for it', () => {
    const r = response('Loaded', 'Valid', {}, { unknownTier: true, tier: 'enterprise' });
    expect(describeLicence(r).notes.join(' ')).toContain('does not know the Enterprise tier');
    expect(bannerFor(r)).toBeNull();
  });
});

describe('bannerFor', () => {
  it.each([
    ['Expiring', 'amber', 'Your licence expires on 2027-01-15, in 10 days.'],
    ['Grace', 'red', 'Your licence expired on 2027-01-15. Paid features switch off on 2027-02-14.'],
    ['Lapsed', 'grey', 'Your licence lapsed on 2027-02-14. Paid features are off.'],
    ['NotYetValid', 'amber', 'Your licence starts on 2026-01-01. Paid features are off until then.'],
    ['Invalid', 'red', 'The licence file cannot be used, so paid features are off.'],
    ['BindingMismatch', 'red', 'The licence is for another forest, so paid features are off.'],
  ] as const)('a loaded module with %s is %s', (status, tone, text) => {
    const banner = bannerFor(response('Loaded', status));
    expect(banner?.tone).toBe(tone);
    expect(banner?.text).toBe(`${text} ${NOT_AFFECTED}`);
    expect(banner?.dismissible).toBe(tone === 'grey');
  });

  it.each(['Valid', 'StoredNotVerified', 'None'] as const)('a loaded module with %s is quiet', (status) => {
    expect(bannerFor(response('Loaded', status, { active: true }))).toBeNull();
  });

  it('a stored licence with no module is amber, and with a broken module red', () => {
    expect(bannerFor(response('NotPresent', 'StoredNotVerified'))?.tone).toBe('amber');
    for (const state of ['Failed', 'Unresponsive', 'Quarantined', 'Incompatible', 'Refused'] as const) {
      expect(bannerFor(response(state, 'StoredNotVerified'))?.tone).toBe('red');
    }
  });

  it('a later lapse of another licence carries another key, so a dismissal does not hide it', () => {
    const first = bannerFor(response('Loaded', 'Lapsed'));
    const second = bannerFor(response('Loaded', 'Lapsed', {}, { licenceId: 'lid-2', graceUntil: '2028-02-14T00:00:00Z' }));
    expect(first?.key).not.toBe(second?.key);
  });

  it('nothing before the status has loaded', () => {
    expect(bannerFor(undefined)).toBeNull();
  });
});

describe('aboutTier', () => {
  it.each([
    [response('NotPresent', 'None'), 'Free tier'],
    [response('Loaded', 'Valid'), 'Standard'],
    [response('Loaded', 'Valid', {}, { unknownTier: true }), 'Standard (tier not known to this paid module)'],
    [response('Loaded', 'Expiring'), 'Standard, expires 2027-01-15'],
    [response('Loaded', 'Grace'), 'Standard, paid features end 2027-02-14'],
    [response('Loaded', 'NotYetValid'), 'Free tier until 2026-01-01'],
    [response('Loaded', 'Lapsed'), 'Free tier (licence lapsed 2027-02-14)'],
    [response('Loaded', 'BindingMismatch'), 'Free tier (licence is for another forest)'],
    [response('Loaded', 'Invalid'), 'Free tier (licence file cannot be used)'],
    [response('Loaded', 'StoredNotVerified'), 'Free tier (licence not checked yet)'],
    [response('NotPresent', 'StoredNotVerified'), 'Free tier (paid module not installed)'],
    [response('Quarantined', 'StoredNotVerified'), 'Free tier (paid module not running)'],
    [response('Loaded', 'None', { active: false, untrusted: true }), 'Free tier (licence folder cannot be trusted)'],
  ])('%#: %s', (r, expected) => {
    expect(aboutTier(r)).toBe(expected);
  });

  it('nothing before the status has loaded', () => {
    expect(aboutTier(undefined)).toBeNull();
  });
});

describe('reasonWords', () => {
  it.each([
    'TooLarge', 'MalformedEnvelope', 'BadEncoding', 'UnsupportedHeader', 'UnknownKey', 'BadSignature',
    'MalformedClaims', 'UnsupportedClaims', 'UnsupportedVersion', 'Revoked', 'OutOfBounds',
  ])('words %s plainly, without naming the code', (code) => {
    const words = reasonWords(code);
    expect(words).not.toContain(code);
    expect(words).not.toMatch(/[–—]/);
  });

  it('points a wrapped paste at the file itself', () => {
    expect(reasonWords('MalformedEnvelope')).toContain('choose the file instead');
    expect(reasonWords('BadEncoding')).toContain('choose the file instead');
  });

  it('still shows a code it does not know', () => {
    expect(reasonWords('SomethingNew')).toBe('the paid module refused it (reason SomethingNew)');
    expect(reasonWords(null)).toBe('the paid module could not read it');
  });
});

describe('describeCandidate', () => {
  const inspect = (state: ModuleState, candidate: LicenceInspectResponse['candidate']): LicenceInspectResponse => ({
    module: module(state),
    candidate,
  });

  it('a verified candidate can be activated, and carries the downgrade flag', () => {
    const verdict = describeCandidate(inspect('Loaded', { licence: licence('Valid'), worseThanInstalled: true }));
    expect(verdict).toEqual({ kind: 'verified', summary: 'This licence is valid until 2027-01-15.', worse: true, notes: [] });
  });

  it('carries the same notes the card would show once installed', () => {
    const verdict = describeCandidate(inspect('Loaded', {
      licence: licence('Valid', { clockAnomaly: true }),
      worseThanInstalled: false,
    }));
    expect(verdict.kind === 'verified' && verdict.notes.join(' ')).toContain("This server's clock looks wrong");
  });

  it('an invalid candidate cannot be activated', () => {
    const verdict = describeCandidate(inspect('Loaded', { licence: licence('Invalid'), worseThanInstalled: false }));
    expect(verdict.kind).toBe('invalid');
    expect(verdict.summary).toContain('its signature does not match');
  });

  it('a loaded module that could not judge the file offers nothing to install', () => {
    expect(describeCandidate(inspect('Loaded', null)).kind).toBe('unjudged');
  });

  it('with no module running the file can still be stored', () => {
    for (const state of ['NotPresent', 'Failed', 'Incompatible', 'Refused'] as const) {
      expect(describeCandidate(inspect(state, null)).kind).toBe('noModule');
    }
  });

  it('a lapsed or mismatched candidate is still verified, and says it switches nothing on', () => {
    const lapsed = describeCandidate(inspect('Loaded', { licence: licence('Lapsed'), worseThanInstalled: true }));
    expect(lapsed.kind).toBe('verified');
    expect(lapsed.summary).toContain('would switch no paid features on');

    const mismatch = describeCandidate(inspect('Loaded', { licence: licence('BindingMismatch'), worseThanInstalled: false }));
    expect(mismatch.summary).toBe(
      'This licence is for corp.example.com. This server is in other.example.com. It would switch no paid features on here.');
  });
});

describe('licenceFacts', () => {
  it('shows nothing an unverified file says, only this server\'s forest', () => {
    expect(licenceFacts(licence('Invalid'))).toEqual([{ label: "This server's forest", value: 'other.example.com' }]);
  });

  it('lists a verified licence', () => {
    const labels = licenceFacts(licence('Valid')).map((f) => f.label);
    expect(labels).toEqual([
      'Licensed to', 'Reference', 'Tier', 'Connected CAs', 'Valid from', 'Valid until',
      'Paid features end', 'Bound to', "This server's forest", 'Licence id',
    ]);
  });

  it('reads 999 CAs as no limit, and no binding as any forest', () => {
    const facts = licenceFacts(licence('Valid', { maxCas: 999, boundForests: [] }));
    expect(facts).toContainEqual({ label: 'Connected CAs', value: 'No limit' });
    expect(facts).toContainEqual({ label: 'Bound to', value: 'Any forest' });
  });
});

describe('small helpers', () => {
  it('isoDate reads the instant in UTC and does no arithmetic', () => {
    expect(isoDate('2027-01-15T00:00:00+00:00')).toBe('2027-01-15');
    expect(isoDate('2027-01-15T01:00:00+02:00')).toBe('2027-01-14');
    expect(isoDate(null)).toBeNull();
    expect(isoDate('not a date')).toBeNull();
  });

  it('daysPhrase words the server\'s whole days', () => {
    expect(daysPhrase(0)).toBe('in less than a day');
    expect(daysPhrase(1)).toBe('in 1 day');
    expect(daysPhrase(12)).toBe('in 12 days');
    expect(daysPhrase(null)).toBeNull();
  });

  it('casPhrase and tierName', () => {
    expect(casPhrase(1)).toBe('up to 1 CA');
    expect(casPhrase(3)).toBe('up to 3 CAs');
    expect(casPhrase(999)).toBe('with no limit on CAs');
    expect(casPhrase(null)).toBeNull();
    expect(tierName('standard')).toBe('Standard');
  });

  it('forestList', () => {
    expect(forestList(['a.example'])).toBe('a.example');
    expect(forestList(['a.example', 'b.example'])).toBe('a.example and b.example');
    expect(forestList(['a.example', 'b.example', 'c.example'])).toBe('a.example, b.example and c.example');
  });

  it('isSetAside mirrors the server: Retry for a failed, unresponsive or quarantined module only', () => {
    expect(MODULE_STATES.filter(isSetAside)).toEqual(['Failed', 'Unresponsive', 'Quarantined']);
  });
});

describe('the browser clock', () => {
  afterEach(() => {
    vi.useRealTimers();
  });

  // Design section 9.1: the browser never counts days. Run every pair under two
  // clocks years apart; anything that read Date.now() would answer differently.
  it('changes nothing anywhere', () => {
    const render = () =>
      EVERY_PAIR.map(([state, status]) => {
        const r = response(state, status);
        return JSON.stringify([describeLicence(r), bannerFor(r), aboutTier(r)]);
      });

    vi.useFakeTimers();
    vi.setSystemTime(new Date('2020-06-01T00:00:00Z'));
    const early = render();
    vi.setSystemTime(new Date('2035-06-01T00:00:00Z'));
    const late = render();

    expect(late).toEqual(early);
  });
});
