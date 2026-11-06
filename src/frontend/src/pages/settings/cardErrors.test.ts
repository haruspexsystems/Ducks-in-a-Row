import { describe, expect, it } from 'vitest';

// Every Settings card that catches a failed call shows errorText from
// @/api/client, never the caught error's own message (issue #543). An
// ApiError's message is "API error <status>: <reason> (<url>)", which is a
// developer's string; the reason alone is what an administrator should read.
// The dashboard wide HTTPS certificate banner is held to the same rule,
// because its Apply button makes the same call as the one on this page.
// There is no DOM environment for a component test (see vite.config.ts), so
// this reads the sources as text, the way src/lib/support.test.ts reads
// SUPPORT.md.

const sources = {
  ...import.meta.glob<string>('./*.tsx', { query: '?raw', import: 'default', eager: true }),
  ...import.meta.glob<string>('../../components/HttpsCertificateNoticeBanner.tsx', {
    query: '?raw',
    import: 'default',
    eager: true,
  }),
};

/** A caught error's own message, in the two shapes the cards used to show it. */
const OWN_MESSAGE = [/instanceof Error\s*\?\s*\w+\.message\b/, /\b(?:err|error|e)\.message\b/];

describe('Settings card error text', () => {
  it('reads the card sources', () => {
    // Without this, a moved folder would make the check below pass on nothing.
    expect(Object.keys(sources)).toEqual(
      expect.arrayContaining([
        './AlertsCard.tsx',
        './AllowedDomainsCard.tsx',
        './ExternalUrlCard.tsx',
        './HttpsCertificateSection.tsx',
        './LicenceCard.tsx',
        './LicenceUpload.tsx',
        './RevocationScopeCard.tsx',
        '../../components/HttpsCertificateNoticeBanner.tsx',
      ]),
    );
  });

  it.each(Object.entries(sources))('%s never shows a caught error\'s own message', (_, source) => {
    const lines = source
      .split(/\r?\n/)
      .map((line, i) => `${i + 1}: ${line.trim()}`)
      .filter((line) => OWN_MESSAGE.some((shape) => shape.test(line)));

    expect(lines).toEqual([]);
  });
});
