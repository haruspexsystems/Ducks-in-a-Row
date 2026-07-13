import { Link, Outlet, useLocation } from 'react-router-dom';
import { useQuery } from '@tanstack/react-query';
import { FlaskConical, LayoutDashboard, List, Settings } from 'lucide-react';
import { DuckMark } from '@/features/dashboard/components/DuckMark';
import { ACCENT, NAV_BG, NAV_BORDER } from '@/features/dashboard/lib/colors';
import { fetchSetupConfig } from '@/api/setup';

const navItems = [
  { path: '/', label: 'Dashboard', icon: LayoutDashboard },
  { path: '/certificates', label: 'Certificates', icon: List },
  { path: '/settings', label: 'Settings', icon: Settings },
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

export function Layout() {
  const location = useLocation();

  return (
    <div className="min-h-screen bg-[#F6F7F9]">
      <MockCaBanner />
      {/* Top navigation bar — deep-slate brand chrome */}
      <header className="border-b" style={{ background: NAV_BG, borderColor: NAV_BORDER }}>
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
              {navItems.map(({ path, label, icon: Icon }) => {
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
            </nav>
          </div>
        </div>
      </header>

      {/* Main content */}
      <main className="max-w-screen-2xl mx-auto px-4 sm:px-6 lg:px-8 py-6">
        <Outlet />
      </main>
    </div>
  );
}
