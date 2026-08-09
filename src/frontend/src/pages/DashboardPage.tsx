import { RefreshCw } from 'lucide-react';
import { useDashboardData } from '@/features/dashboard/data/queries';
import { useManualSync } from '@/hooks/useSyncStatus';
import { ApiErrorNotice } from '@/components/ApiErrorNotice';
import { HeaderSyncStatus } from '@/components/HeaderSyncStatus';
import { SyncErrorNotice } from '@/components/SyncErrorNotice';
import { StatCard } from '@/features/dashboard/components/StatCard';
import { RegistrationsChart } from '@/features/dashboard/components/RegistrationsChart';
import { FleetHealth } from '@/features/dashboard/components/FleetHealth';
import { ValidationMethods } from '@/features/dashboard/components/ValidationMethods';
import { ActivityTable } from '@/features/dashboard/components/ActivityTable';
import { QuickActions } from '@/features/dashboard/components/QuickActions';
import '@/features/dashboard/dashboard-theme.css';

export function DashboardPage() {
  const { data, isLoading, error, refetch, isFetching } = useDashboardData();

  // Refresh = pull the inventory from the CA, then refetch. A failure surfaces
  // as a dismissible notice and in the header instead of being swallowed, and
  // never blocks the refetch of what is already local (issue #157).
  const { syncing, syncError, runSync, dismissSyncError } = useManualSync(refetch);

  if (error) {
    return <ApiErrorNotice error={error} title="Failed to load the dashboard" />;
  }

  const valueOf = (key: string) => data?.stats.find((s) => s.key === key)?.value ?? 0;

  return (
    <div className="md-dashboard">
      {/* page header */}
      <div className="mb-[18px] flex items-end justify-between gap-3">
        <div>
          <h1 className="text-2xl font-bold text-ink">Dashboard</h1>
          <HeaderSyncStatus lead="Certificate inventory overview" />
        </div>
        <button
          type="button"
          onClick={runSync}
          className="inline-flex items-center gap-2 rounded-lg border border-hairline bg-surface px-3.5 py-2 text-sm font-semibold text-ink-soft transition-colors hover:bg-sunken disabled:opacity-60"
          disabled={syncing || isFetching}
        >
          <RefreshCw className={`h-4 w-4 ${syncing || isFetching ? 'animate-spin' : ''}`} />
          Refresh
        </button>
      </div>

      {/* A failed manual sync, with the problem detail and its remediation */}
      {syncError != null && (
        <div className="mb-[18px]">
          <SyncErrorNotice error={syncError} onDismiss={dismissSyncError} />
        </div>
      )}

      {isLoading || !data ? (
        <div className="flex items-center justify-center rounded-2xl border border-hairline bg-surface py-24 text-sm text-muted">
          Loading dashboard…
        </div>
      ) : (
        <div className="flex flex-col gap-[18px]">
          {/* stat cards */}
          <div className="grid grid-cols-1 gap-[18px] sm:grid-cols-2 lg:grid-cols-5">
            {data.stats.map((c) => (
              <StatCard key={c.key} data={c} />
            ))}
          </div>

          {/* issuance + fleet health */}
          <div className="grid grid-cols-1 gap-[18px] lg:grid-cols-[1.92fr_1fr]">
            <RegistrationsChart data={data.registrations} />
            <FleetHealth data={data.health} />
          </div>

          {/* activity + (validation / quick actions) */}
          <div className="grid grid-cols-1 items-start gap-[18px] lg:grid-cols-[1.92fr_1fr]">
            <ActivityTable data={data.activity} />
            <div className="flex flex-col gap-[18px]">
              <ValidationMethods data={data.validation} />
              <QuickActions
                total={valueOf('total')}
                expiring={valueOf('expiring')}
                expired={valueOf('expired')}
                revoked={valueOf('revoked')}
                warningDays={data.warningDays}
              />
            </div>
          </div>
        </div>
      )}
    </div>
  );
}
