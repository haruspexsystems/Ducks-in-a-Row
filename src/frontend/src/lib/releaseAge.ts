// releaseAge.ts — the words the Settings About block uses for the installed
// release's age (issue #623). The server computes the age and the verdict
// (/api/settings/info: releaseAgeDays, releaseAgeWarningDays, releaseOutdated),
// so the dashboard never compares dates itself and the two clocks that could
// disagree (the server's and the browser's) never meet. This file only turns
// the numbers into sentences, which is why it is testable without a page.

/**
 * The commit date as a calendar day, read in UTC. The stamp is an instant in
 * UTC and the server counts the age from it, so the day shown must be the
 * same in every browser; the shared formatDate uses the browser's own zone,
 * which would show the day before to anyone west of UTC for a commit stamped
 * near midnight. Same en-US short form as the rest of the dashboard.
 */
export function formatReleaseDate(commitDate: string): string {
  return new Date(commitDate).toLocaleDateString('en-US', {
    year: 'numeric',
    month: 'short',
    day: 'numeric',
    timeZone: 'UTC',
  });
}

/** "today", "1 day ago" or "N days ago", for the Released row. */
export function describeReleaseAge(ageDays: number): string {
  if (ageDays <= 0) return 'today';
  if (ageDays === 1) return '1 day ago';
  return `${ageDays} days ago`;
}

/**
 * The warning the About block shows once the age passed the threshold. It
 * names both numbers so an operator who raised the threshold on purpose can
 * see that the page is applying their value and not the default.
 */
export function describeOutdatedRelease(ageDays: number, warningDays: number): string {
  return (
    `This release is ${ageDays} days old, past the ${warningDays} day threshold, ` +
    'so a newer one may exist.'
  );
}
