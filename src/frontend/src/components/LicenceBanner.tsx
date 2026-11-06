import { useState } from 'react';
import { Link } from 'react-router';
import { AlertTriangle, Info, X } from 'lucide-react';
import { useLicence } from '@/hooks/useLicence';
import { bannerFor, type LicenceBanner as Banner } from '@/lib/licence';

const DISMISSED_KEY = 'diar-licence-banner-dismissed';

const toneClasses: Record<Banner['tone'], string> = {
  amber: 'bg-amber-400 text-amber-950',
  red: 'bg-red-600 text-red-50',
  grey: 'bg-sunken-strong text-ink-soft border-b border-hairline',
};

/** The dismissed banner's key for this browser session, or null. Storage can be blocked, so it never throws. */
function readDismissed(): string | null {
  try {
    return sessionStorage.getItem(DISMISSED_KEY);
  } catch {
    return null;
  }
}

function writeDismissed(key: string) {
  try {
    sessionStorage.setItem(DISMISSED_KEY, key);
  } catch {
    // Storage blocked: the dismissal lasts until the page reloads, which is the most it can do.
  }
}

/**
 * Dashboard wide notice about the licence (licence design section 13.5, issue
 * #493): amber while the licence is expiring, red in grace, grey once it has
 * lapsed, and amber or red whenever a stored licence switches nothing on for
 * another reason. It speaks only when a licence is stored, so a free
 * installation never sees it, and it shows the server's own day count: unlike
 * the HTTPS certificate banner, it never counts days from the browser's clock.
 *
 * Only the grey banner can be dismissed, for the browser session, and the
 * dismissal names what it hid, so a later lapse of another licence shows again.
 */
export function LicenceBanner() {
  const { data, isError } = useLicence();
  const [dismissed, setDismissed] = useState(readDismissed);

  const banner = isError ? null : bannerFor(data);
  if (!banner || (banner.dismissible && dismissed === banner.key)) {
    return null;
  }

  const Icon = banner.tone === 'grey' ? Info : AlertTriangle;

  return (
    <div className={toneClasses[banner.tone]} role="status" data-testid="licence-banner">
      <div className="max-w-screen-2xl mx-auto px-4 sm:px-6 lg:px-8 py-1.5 flex flex-wrap items-center gap-2 text-xs font-semibold">
        <Icon className="h-3.5 w-3.5" />
        <span>{banner.text}</span>
        <Link to="/settings#licence" className="font-medium underline underline-offset-2 hover:no-underline">
          Open the licence settings
        </Link>
        {banner.dismissible && (
          <button
            type="button"
            onClick={() => {
              writeDismissed(banner.key);
              setDismissed(banner.key);
            }}
            aria-label="Dismiss for this session"
            className="ml-auto rounded p-0.5 hover:bg-black/10 dark:hover:bg-white/10"
          >
            <X className="h-3.5 w-3.5" />
          </button>
        )}
      </div>
    </div>
  );
}
