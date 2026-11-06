import { describe, it, expect } from 'vitest';
import { describeAction, describeChange, describeSignInFailures } from './audit';

/**
 * Issue #634. The server records dotted action names and raw values; these
 * are the sentences the Audit page makes of them.
 */
describe('describeAction', () => {
  it('opens the dotted name into an area and a sentence fragment', () => {
    expect(describeAction('settings.allowed-domains.changed')).toBe('Settings: allowed domains changed');
    expect(describeAction('acme.eab-credential.secret-regenerated'))
      .toBe('ACME: EAB credential secret regenerated');
    expect(describeAction('settings.https-certificate.renewal-requested')).toBe('Settings: HTTPS certificate renewal requested');
    expect(describeAction('certificate.revoked')).toBe('Certificates: revoked');
    expect(describeAction('other.thing.done')).toBe('Other: thing done');
  });

  it('falls back to the raw name for a shape it does not know', () => {
    expect(describeAction('legacy')).toBe('legacy');
    expect(describeAction('')).toBe('');
  });
});

describe('describeSignInFailures', () => {
  it('says so when nothing was refused', () => {
    expect(describeSignInFailures(0, 0, 30)).toBe('No refused sign ins in the last 30 days.');
    expect(describeSignInFailures(0, 0, 1)).toBe('No refused sign ins in the last day.');
  });

  it('counts attempts and sources, singular and plural', () => {
    expect(describeSignInFailures(1, 1, 7)).toBe('1 refused sign in from 1 source address in the last 7 days.');
    expect(describeSignInFailures(12, 3, 30)).toBe('12 refused sign ins from 3 source addresses in the last 30 days.');
  });
});

describe('describeChange', () => {
  it('shows before and after when both are known', () => {
    expect(describeChange('off', 'on: example.com')).toBe('off → on: example.com');
  });

  it('shows after alone, before alone, or a dash', () => {
    expect(describeChange(null, 'revoked at the CA, reason 1')).toBe('revoked at the CA, reason 1');
    expect(describeChange('old', null)).toBe('was old');
    expect(describeChange(null, null)).toBe('—');
    expect(describeChange(undefined, '')).toBe('—');
  });
});
