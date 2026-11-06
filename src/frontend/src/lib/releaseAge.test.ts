import { describe, it, expect } from 'vitest';
import { describeOutdatedRelease, describeReleaseAge, formatReleaseDate } from './releaseAge';

/**
 * Issue #623. The numbers come from the server; these are the sentences the
 * About block makes of them. Small, but the plural and the two numbers in
 * the warning are exactly what a careless edit would break.
 */
describe('describeReleaseAge', () => {
  it('says today for a release stamped today or by a clock behind the commit', () => {
    expect(describeReleaseAge(0)).toBe('today');
    expect(describeReleaseAge(-1)).toBe('today');
  });

  it('handles the singular', () => {
    expect(describeReleaseAge(1)).toBe('1 day ago');
  });

  it('counts days otherwise', () => {
    expect(describeReleaseAge(2)).toBe('2 days ago');
    expect(describeReleaseAge(181)).toBe('181 days ago');
  });
});

describe('formatReleaseDate', () => {
  it('shows the UTC calendar day whatever zone the browser is in', () => {
    // A stamp at midnight UTC is the one a local zone formatter would move
    // to the day before. The server counts the age from 1 March, so the page
    // must say 1 March too.
    expect(formatReleaseDate('2026-03-01T00:00:00.0000000+00:00')).toBe('Mar 1, 2026');
    expect(formatReleaseDate('2026-10-22T23:59:59Z')).toBe('Oct 22, 2026');
  });
});

describe('describeOutdatedRelease', () => {
  it('names the age and the threshold in force, so a raised threshold is visible', () => {
    expect(describeOutdatedRelease(200, 180)).toBe(
      'This release is 200 days old, past the 180 day threshold, so a newer one may exist.',
    );
    expect(describeOutdatedRelease(400, 365)).toContain('past the 365 day threshold');
  });
});
