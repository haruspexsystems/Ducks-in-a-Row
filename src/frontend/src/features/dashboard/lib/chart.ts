// chart.ts — shared SVG chart math used by the bar chart.

/** Round a data max up to a "nice" axis ceiling. */
export function niceMax(m: number): number {
  return Math.max(10, Math.ceil((m * 1.12) / 10) * 10);
}

const MONTHS = ['Jan', 'Feb', 'Mar', 'Apr', 'May', 'Jun', 'Jul', 'Aug', 'Sep', 'Oct', 'Nov', 'Dec'];

/** "Jun 6"-style label for N days before today. */
export function dateLabel(daysAgo: number): string {
  const d = new Date();
  d.setDate(d.getDate() - daysAgo);
  return `${MONTHS[d.getMonth()]} ${d.getDate()}`;
}
