import { describe, it, expect } from 'vitest';
import * as support from './support';
// The repository's own SUPPORT.md and SECURITY.md, read as text through Vite's ?raw
// import, so the check needs no Node types in a browser tsconfig.
import supportMd from '../../../../SUPPORT.md?raw';
import securityMd from '../../../../SECURITY.md?raw';

/**
 * The outward links a shipped build carries (issues #242 and #253). Every one
 * of them is baked into a build for as long as it is installed, so the two
 * things worth pinning are where they may point and the one address a page on
 * the website has to keep answering at.
 */
describe('support links', () => {
  const urls = Object.entries(support).filter(([, v]) => typeof v === 'string') as [string, string][];

  it('exports the links the dashboard and the wizard use', () => {
    expect(urls.map(([name]) => name).sort()).toEqual([
      'FEEDBACK_MAILTO',
      'MONITOR_MODE_URL',
      'RELEASES_URL',
      'SECURITY_ADVISORIES_URL',
      'SECURITY_NOTICES_URL',
      'SUPPORT_DISCUSSIONS_URL',
      'SUPPORT_GITHUB_URL',
    ]);
  });

  it.each(urls)('%s points at the public repository, the website or our mail', (_, value) => {
    const allowed =
      value.startsWith('https://github.com/haruspexsystems/Ducks-in-a-Row') ||
      value.startsWith('https://ducksinarow.dev/') ||
      value.startsWith('mailto:feedback@haruspex.systems?');
    expect(allowed).toBe(true);
  });

  it.each(urls)('%s names neither the private repository nor a domain that is not ours', (_, value) => {
    expect(value).not.toMatch(/lethe377|ducksinarow\.app/i);
  });

  it('points the monitor mode badge at the problem type page the server emits', () => {
    // The same URI as DashboardProblemType.MonitorMode, so a refusal and the
    // badge lead to one page; that page is a contract with every build.
    expect(support.MONITOR_MODE_URL).toBe('https://ducksinarow.dev/problems/monitor-mode');
  });

  it('keeps the security notices sign up on the notices page', () => {
    // Shipped builds link here for good. Moving the sign up means a new page
    // and a new constant, with this page kept working for the builds already out.
    expect(support.SECURITY_NOTICES_URL).toBe('https://ducksinarow.dev/notices');
  });

  it('names the same sign up and advisories in SUPPORT.md and SECURITY.md', () => {
    // support.ts says these move together. Without this, changing the constant
    // and missing a document sends readers of the docs somewhere else.
    expect(supportMd).toContain(support.SECURITY_NOTICES_URL);
    expect(supportMd).toContain(support.SECURITY_ADVISORIES_URL);
    expect(supportMd).toContain(support.SUPPORT_DISCUSSIONS_URL);
    expect(securityMd).toContain(support.SECURITY_NOTICES_URL);
  });

  it('carries nothing that could identify the installation that sent the visitor', () => {
    expect(support.SECURITY_NOTICES_URL).not.toContain('?');
    expect(support.SECURITY_NOTICES_URL).not.toContain('#');
    expect(support.RELEASES_URL).not.toContain('?');
  });

  it('points the release age notice at the public releases page', () => {
    // Issue #623: the one place an operator is sent to find a newer release.
    // A build carries it for life, so it is the public repository's releases
    // page and nothing that could move.
    expect(support.RELEASES_URL).toBe('https://github.com/haruspexsystems/Ducks-in-a-Row/releases');
  });
});
