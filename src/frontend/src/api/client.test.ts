import { afterEach, describe, expect, it, vi } from 'vitest';
import { sendTestAlert } from './alerts';
import { ApiError, errorText, fetchJson } from './client';
import { installLicence, removeLicence } from './licence';
import {
  applyHttpsCertificate,
  renewHttpsCertificate,
  updateAllowedDomains,
  updateExternalUrl,
  updateRevocationScope,
} from './settings';
import { validateExternalUrl } from './setup';

// What a Settings card shows when a call fails (issue #543). Before this, every
// card showed the ApiError's message, which reads
// "API error <status>: <reason> (<url>)" where the reason alone was meant.

const FALLBACK = 'Saving failed';

describe('errorText', () => {
  it('shows the sentence a plain fetch helper read from the body, and nothing else', () => {
    const err = new ApiError(503, 'The settings file could not be read.', '/api/settings/external-url');

    expect(errorText(err, FALLBACK)).toBe('The settings file could not be read.');
  });

  it('prefers the problem detail fetchJson read, over the reason phrase beside it', () => {
    const err = new ApiError(
      403, 'Forbidden', '/api/alerts/config/apply',
      'https://ducksinarow.dev/problems/monitor-mode', 'Not available in monitor mode',
      'This instance runs in monitor mode.');

    expect(errorText(err, FALLBACK)).toBe('This instance runs in monitor mode.');
  });

  it('reads an empty problem detail as absent', () => {
    const err = new ApiError(500, 'Internal Server Error', '/api/x', undefined, undefined, '');

    expect(errorText(err, FALLBACK)).toBe('Internal Server Error');
  });

  it('falls back when the server said nothing, as over HTTP/2 where the reason phrase is empty', () => {
    expect(errorText(new ApiError(500, '', '/api/settings/allowed-domains'), FALLBACK)).toBe(FALLBACK);
  });

  it('keeps the message of an error that is not an ApiError', () => {
    expect(errorText(new TypeError('Failed to fetch'), FALLBACK)).toBe('Failed to fetch');
  });

  it('falls back for an error with no message', () => {
    expect(errorText(new Error(''), FALLBACK)).toBe(FALLBACK);
  });

  it.each([undefined, null, 'a string', 42, { message: 'not an Error' }])(
    'falls back for a thrown %j',
    (thrown) => {
      expect(errorText(thrown, FALLBACK)).toBe(FALLBACK);
    },
  );
});

/**
 * The same, through the real helpers, so the pairing is pinned at the source:
 * each call a Settings card makes, answered the way the server answers a
 * refusal. The message assertion records what the card used to show.
 */
describe('errorText over the calls the Settings cards make', () => {
  afterEach(() => {
    vi.unstubAllGlobals();
  });

  function answer(status: number, body: unknown, statusText = '') {
    vi.stubGlobal(
      'fetch',
      vi.fn(async () =>
        new Response(body === undefined ? null : JSON.stringify(body), {
          status,
          statusText,
          headers: { 'Content-Type': 'application/json' },
        }),
      ),
    );
  }

  async function failureOf(call: () => Promise<unknown>): Promise<unknown> {
    try {
      await call();
    } catch (err) {
      return err;
    }
    throw new Error('The call was expected to fail.');
  }

  const SENTENCE = 'The settings file could not be read, so nothing was changed.';

  it.each([
    ['updateExternalUrl', '/api/settings/external-url', () => updateExternalUrl('https://ducks.example')],
    ['updateAllowedDomains', '/api/settings/allowed-domains', () => updateAllowedDomains(true, ['example.com'])],
    ['updateRevocationScope', '/api/settings/revocation-scope', () => updateRevocationScope('all', [])],
    ['renewHttpsCertificate', '/api/settings/https-certificate/renew', () => renewHttpsCertificate()],
    ['applyHttpsCertificate', '/api/settings/https-certificate/apply', () => applyHttpsCertificate()],
    ['sendTestAlert', '/api/alerts/test', () => sendTestAlert()],
    ['removeLicence', '/api/settings/licence', () => removeLicence()],
    ['installLicence', '/api/settings/licence', () => installLicence(new Blob(['x']))],
  ])('%s shows the server sentence alone', async (_, url, call) => {
    answer(503, { error: SENTENCE }, 'Service Unavailable');

    const err = await failureOf(call);

    expect(err).toBeInstanceOf(ApiError);
    expect((err as ApiError).message).toBe(`API error 503: ${SENTENCE} (${url})`);
    expect(errorText(err, FALLBACK)).toBe(SENTENCE);
  });

  it('shows the message a renewal arm sends', async () => {
    answer(502, { error: true, message: 'The CA refused the request.' });

    const err = await failureOf(() => renewHttpsCertificate());

    expect(errorText(err, FALLBACK)).toBe('The CA refused the request.');
  });

  it('shows the detail of a problem document read through fetchJson', async () => {
    answer(403, {
      type: 'https://ducksinarow.dev/problems/monitor-mode',
      title: 'Not available in monitor mode',
      detail: 'This instance runs in monitor mode.',
    }, 'Forbidden');

    const err = await failureOf(() => validateExternalUrl('https://ducks.example'));

    expect(errorText(err, FALLBACK)).toBe('This instance runs in monitor mode.');
  });

  it('falls back when a refusal has no body and no reason phrase', async () => {
    answer(500, undefined);

    expect(errorText(await failureOf(() => updateExternalUrl('https://ducks.example')), FALLBACK)).toBe(FALLBACK);
    expect(errorText(await failureOf(() => fetchJson('/api/alerts/config/apply')), FALLBACK)).toBe(FALLBACK);
  });
});
