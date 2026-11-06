import { RELEASES_URL, SECURITY_NOTICES_URL } from '@/lib/support';

interface ReleaseNoticeProps {
  className?: string;
}

const linkClass =
  'text-certus-600 hover:text-certus-800 dark:text-certus-300 underline underline-offset-2';

/**
 * Why the product cannot tell the operator about a newer release, and what
 * to do instead (issue #623, Sean's decision of 2026-10-21). Ducks in a Row
 * never contacts the internet, by a permanent design rule, so the duty to
 * inform about updates is met by saying so plainly at the two moments that
 * matter: once on the Setup Complete page and permanently on the Settings
 * About block, where the release's age sits beside it. No check box: a box
 * the administrator must tick changes no security property and adds a step
 * to every install.
 *
 * Both links are plain anchors, for the reasons SecurityNotices gives: the
 * Content Security Policy permits a top level navigation and nothing else
 * cross origin, and `rel="noopener noreferrer"` keeps the Referer from
 * telling the site which server the click came from. The page requests
 * nothing; the operator's browser opens what the operator clicks.
 */
export function ReleaseNotice({ className = '' }: ReleaseNoticeProps) {
  return (
    <p className={`text-sm text-muted ${className}`}>
      Ducks in a Row never contacts the internet, so it cannot check for updates. Check the{' '}
      <a href={RELEASES_URL} target="_blank" rel="noopener noreferrer" className={linkClass}>
        releases page
      </a>{' '}
      from time to time, and{' '}
      <a href={SECURITY_NOTICES_URL} target="_blank" rel="noopener noreferrer" className={linkClass}>
        sign up for security notices
      </a>{' '}
      to hear when a release fixes a vulnerability.
    </p>
  );
}
