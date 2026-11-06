import { Link, Outlet, useLocation } from 'react-router';
import { useQuery } from '@tanstack/react-query';
import { ExternalLink, Eye, FlaskConical, KeyRound, LayoutDashboard, List, ScrollText, Settings } from 'lucide-react';
import { DuckMark } from '@/features/dashboard/components/DuckMark';
import { ACCENT } from '@/features/dashboard/lib/colors';
import { fetchSetupConfig } from '@/api/setup';
import { HttpsCertificateNoticeBanner } from '@/components/HttpsCertificateNoticeBanner';
import { LicenceBanner } from '@/components/LicenceBanner';
import { MonitorModeAlertsBanner } from '@/components/MonitorModeAlertsBanner';
import { SupportFooter } from '@/components/SupportFooter';
import { ThemeToggle } from '@/components/ThemeToggle';
import { useMonitorMode } from '@/hooks/useSystemInfo';
import { MONITOR_MODE_URL } from '@/lib/support';

const navItems = [
  { path: '/', label: 'Dashboard', icon: LayoutDashboard },
  { path: '/certificates', label: 'Certificates', icon: List },
  // Not in monitor mode (issue #470), where there is no ACME to administer.
  { path: '/acme', label: 'ACME', icon: KeyRound, fullModeOnly: true },
  { path: '/settings', label: 'Settings', icon: Settings },
  // The administrator audit trail (issue #634), read only.
  { path: '/audit', label: 'Audit', icon: ScrollText },
];

/**
 * Persistent banner while the mock CA is active: every certificate is fake,
 * and that must never look like a healthy production dashboard.
 */
function MockCaBanner() {
  const { data } = useQuery({
    queryKey: ['setup-config'],
    queryFn: fetchSetupConfig,
    staleTime: 5 * 60_000,
    retry: false,
    // The CA mode only changes across a service restart; no point refetching
    // on every tab focus.
    refetchOnWindowFocus: false,
  });

  if (data?.caMode !== 'mock') {
    return null;
  }

  return (
    <div className="bg-amber-400 text-amber-950">
      <div className="max-w-screen-2xl mx-auto px-4 sm:px-6 lg:px-8 py-1.5 flex items-center gap-2 text-xs font-semibold">
        <FlaskConical className="h-3.5 w-3.5" />
        Mock CA mode — certificates are fake. For development and demos only.
      </div>
    </div>
  );
}

/**
 * Persistent badge while the server runs in monitor mode (issue #470): it
 * watches the CA and never issues or revokes, so an operator must never mistake
 * the missing controls for a fault. A calm tone rather than the mock CA's
 * amber, because nothing here is wrong. The link leads to the same page the
 * server's monitor mode refusals name.
 */
function MonitorModeBadge() {
  if (!useMonitorMode()) {
    return null;
  }

  return (
    <div className="bg-sky-100 text-sky-900 dark:bg-sky-500/15 dark:text-sky-200">
      <div className="max-w-screen-2xl mx-auto px-4 sm:px-6 lg:px-8 py-1.5 flex items-center gap-2 text-xs font-semibold">
        <Eye className="h-3.5 w-3.5" />
        Monitor mode: never issues or revokes
        <a
          href={MONITOR_MODE_URL}
          target="_blank"
          rel="noopener noreferrer"
          className="inline-flex items-center gap-1 font-medium underline underline-offset-2 hover:no-underline"
        >
          What this means
          <ExternalLink className="h-3 w-3" />
        </a>
      </div>
    </div>
  );
}

export function Layout() {
  const location = useLocation();
  const monitorMode = useMonitorMode();

  return (
    <div className="min-h-screen bg-bg">
      <MockCaBanner />
      <MonitorModeBadge />
      <MonitorModeAlertsBanner />
      <HttpsCertificateNoticeBanner />
      <LicenceBanner />
      {/* Top navigation bar — deep-slate brand chrome, identical in both themes.
          Driven by tokens rather than inline styles: an inline style attribute
          cannot respond to the `.dark` class at all. */}
      <header className="border-b bg-nav-bg border-nav-border">
        <div className="max-w-screen-2xl mx-auto px-4 sm:px-6 lg:px-8">
          <div className="flex items-center justify-between h-16">
            {/* Brand */}
            <Link to="/" className="flex items-center gap-[11px] hover:opacity-90 transition-opacity">
              <div
                className="grid h-10 w-10 place-items-center rounded-[11px]"
                style={{ background: 'rgba(255,255,255,0.06)', boxShadow: 'inset 0 0 0 1px rgba(255,255,255,.07)' }}
              >
                <DuckMark size={30} />
              </div>
              <div className="leading-none">
                <div className="text-[18px] font-extrabold tracking-[-0.4px] text-white">Ducks in a Row</div>
                <div className="mt-[3px] text-[10.5px] font-semibold tracking-[0.3px]" style={{ color: '#7C8AA3' }}>
                  CERTIFICATE LIFECYCLE
                </div>
              </div>
            </Link>

            {/* Navigation */}
            <nav className="flex items-center gap-1">
              {navItems.filter((item) => !(monitorMode && item.fullModeOnly)).map(({ path, label, icon: Icon }) => {
                const isActive = path === '/'
                  ? location.pathname === '/'
                  : location.pathname.startsWith(path);

                return (
                  <Link
                    key={path}
                    to={path}
                    className="flex items-center gap-2 rounded-[10px] px-3.5 py-[9px] text-sm font-semibold transition-colors"
                    style={
                      isActive
                        ? { background: ACCENT, color: '#0C1322' }
                        : undefined
                    }
                  >
                    <span className={isActive ? '' : 'text-[#AEBAD0]'}>
                      <Icon className="h-4 w-4" />
                    </span>
                    <span className={`hidden sm:inline ${isActive ? '' : 'text-[#AEBAD0]'}`}>{label}</span>
                  </Link>
                );
              })}
              <ThemeToggle />
            </nav>
          </div>
        </div>
      </header>

      {/* Main content */}
      <main className="max-w-screen-2xl mx-auto px-4 sm:px-6 lg:px-8 py-6">
        <Outlet />
      </main>

      {/* Reaching us is the same one glance away from every page, because
          nothing is collected and a channel nobody can find is no channel. */}
      <SupportFooter />
    </div>
  );
}
