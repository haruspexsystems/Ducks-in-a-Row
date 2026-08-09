import { Mail, MessagesSquare } from 'lucide-react';
import { FEEDBACK_MAILTO, SUPPORT_DISCUSSIONS_URL } from '@/lib/support';

interface SupportFooterProps {
  /**
   * The container measure of the host shell. The dashboard and the setup
   * wizard are different widths, so the caller supplies it rather than the
   * footer guessing and misaligning with the content above it.
   */
  containerClassName?: string;
}

const linkClass =
  'inline-flex items-center gap-1.5 text-sm text-certus-600 hover:text-certus-800 dark:text-certus-300';

/**
 * A quiet, persistent way to reach the project, at the foot of every dashboard
 * page and of the setup wizard. The product collects no telemetry, so every
 * word we get back is one an operator chose to send, and the way to send it
 * should never be more than a glance away. The setup wizard carries it too
 * because an operator who abandons setup is the one we can least afford to
 * lose track of and the one no other channel will ever hear from.
 *
 * Both entries are plain anchors, deliberately:
 *
 * - The Content Security Policy sends `connect-src 'self'` and
 *   `form-action 'self'`, so a cross origin fetch or form post is refused by
 *   the browser before it leaves the machine. A top level navigation is the
 *   only cross origin act the policy permits.
 * - `rel="noopener noreferrer"` on the Discussions link suppresses the Referer
 *   header, so GitHub is not told the click came from a Ducks in a Row
 *   dashboard. The mailto carries neither attribute, because handing a draft
 *   to a mail client does not navigate the tab.
 * - Nothing is prefilled from anything the app measured. The version and
 *   commit sit on the Settings page for an operator to copy, and reading them
 *   needs administrator rights this footer does not assume.
 *
 * Colours come from the semantic tokens rather than the navigation bar's fixed
 * slate, because the footer sits on the themed page background and has to
 * follow the `.dark` class.
 */
export function SupportFooter({
  containerClassName = 'max-w-screen-2xl mx-auto px-4 sm:px-6 lg:px-8',
}: SupportFooterProps) {
  return (
    <footer className="border-t border-hairline-soft mt-8">
      <div className={`${containerClassName} py-5 flex flex-wrap items-center gap-x-6 gap-y-2`}>
        <span className="text-sm text-muted">Questions, ideas, or something broken?</span>
        <a
          href={SUPPORT_DISCUSSIONS_URL}
          target="_blank"
          rel="noopener noreferrer"
          className={linkClass}
        >
          <MessagesSquare className="h-4 w-4" />
          GitHub Discussions
        </a>
        <a href={FEEDBACK_MAILTO} className={linkClass}>
          <Mail className="h-4 w-4" />
          Send feedback
        </a>
      </div>
    </footer>
  );
}
