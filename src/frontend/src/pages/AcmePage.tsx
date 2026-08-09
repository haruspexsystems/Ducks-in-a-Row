import { Link, useSearchParams } from 'react-router-dom';
import { AcmeAccountsPage } from './acme/AcmeAccountsPage';
import { EabCredentialsCard } from './acme/EabCredentialsCard';
import { EabEnforcementCard } from './acme/EabEnforcementCard';
import { DeviceAttestationCard } from './acme/DeviceAttestationCard';

/**
 * The tabs of the ACME section, in the order an administrator meets them: the
 * inventory they visit daily first, then the settings that produced it.
 */
const TABS = ['accounts', 'credentials', 'policy', 'devices'] as const;

type AcmeTab = (typeof TABS)[number];

const TAB_LABELS: Record<AcmeTab, string> = {
  accounts: 'Accounts',
  credentials: 'Credentials',
  policy: 'Policy',
  devices: 'Devices',
};

const DEFAULT_TAB: AcmeTab = 'accounts';

/**
 * The ACME protocol section (issue #129): who may register and order.
 * Originally one scroll of four cards, which buried the account inventory
 * under about a thousand lines of configure once settings. Each card now has
 * a tab, and the tab lives in the URL, so a filtered account view is a
 * shareable link rather than a scroll position.
 *
 * The tab is a query parameter rather than a path segment, and that is
 * load bearing rather than a style choice. On this server the whole
 * /acme/... path space below the first segment belongs to the ACME protocol:
 * ProtocolPaths.IsAcmeProtocolPath draws the line at "has a second segment",
 * and three separate places depend on it. MapAcmeProtocolFallback answers an
 * unmatched protocol path with an RFC 8555 problem document instead of
 * letting index.html mask a 401 or 404 (issue #27); AcmeNonceMiddleware
 * stamps a Replay-Nonce and forces no-store on anything it considers a
 * protocol path; and the rate limiter's rejection writes an ACME error body.
 * A dashboard route at /acme/accounts would therefore 404 on a hard load,
 * which is exactly what a bookmarkable URL must not do. Keeping the section
 * on the bare segment leaves that boundary alone.
 */
export function AcmePage() {
  const [searchParams] = useSearchParams();

  const raw = searchParams.get('tab');
  const active: AcmeTab = (TABS as readonly string[]).includes(raw ?? '')
    ? (raw as AcmeTab)
    : DEFAULT_TAB;

  return (
    <div className="space-y-6">
      <div>
        <h1 className="text-2xl font-bold text-ink">ACME</h1>
        <p className="text-sm text-muted mt-1">
          Client registration policy, EAB credentials, device attestation, and
          the account inventory
        </p>
      </div>

      {/* Links, not buttons: middle click and open in new tab both work, and
          the browser's back button walks the tabs. Switching tabs replaces
          the whole query string rather than merging into it, because the
          filters belong to the accounts tab alone and would otherwise trail
          behind onto a settings tab that ignores them. */}
      <nav aria-label="ACME sections" className="flex gap-1 border-b border-hairline">
        {TABS.map((tab) => {
          const isActive = tab === active;
          return (
            <Link
              key={tab}
              to={tab === DEFAULT_TAB ? '/acme' : `/acme?tab=${tab}`}
              aria-current={isActive ? 'page' : undefined}
              className={`-mb-px border-b-2 px-4 py-2.5 text-sm font-medium transition-colors ${
                isActive
                  ? 'border-certus-600 text-ink'
                  : 'border-transparent text-muted hover:border-hairline-strong hover:text-ink-soft'
              }`}
            >
              {TAB_LABELS[tab]}
            </Link>
          );
        })}
      </nav>

      {active === 'accounts' && <AcmeAccountsPage />}
      {active === 'credentials' && <EabCredentialsCard />}
      {active === 'policy' && <EabEnforcementCard />}
      {active === 'devices' && <DeviceAttestationCard />}
    </div>
  );
}
