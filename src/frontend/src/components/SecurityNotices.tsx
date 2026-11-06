import { SECURITY_ADVISORIES_URL, SECURITY_NOTICES_URL } from '@/lib/support';

interface SecurityNoticesProps {
  className?: string;
}

const linkClass =
  'text-certus-600 hover:text-certus-800 dark:text-certus-300 underline underline-offset-2';

/**
 * Where an operator signs up to hear about security fixes (issue #242). The
 * product sends us nothing, so a fix we cannot announce reaches nobody who did
 * not ask. It is offered once on the Setup Complete page and kept on the
 * Settings page, and the wording lives here so the two cannot drift.
 *
 * Both entries are plain anchors, for the reasons SupportFooter gives: the
 * Content Security Policy refuses a cross origin fetch or form post, a top
 * level navigation is the only cross origin act it permits, and
 * `rel="noopener noreferrer"` keeps the Referer header from telling either site
 * which server the click came from. The links are underlined because they sit
 * inside a sentence, where colour alone does not mark them.
 */
export function SecurityNotices({ className = '' }: SecurityNoticesProps) {
  return (
    <p className={`text-sm text-muted ${className}`}>
      Ducks in a Row sends us nothing, so we can only tell you about a security fix if you
      ask.{' '}
      <a href={SECURITY_NOTICES_URL} target="_blank" rel="noopener noreferrer" className={linkClass}>
        Sign up for security notices
      </a>{' '}
      on our website, or{' '}
      <a href={SECURITY_ADVISORIES_URL} target="_blank" rel="noopener noreferrer" className={linkClass}>
        watch the security advisories
      </a>{' '}
      on GitHub.
    </p>
  );
}
