import { useState } from 'react';
import { RefreshCw } from 'lucide-react';
import { triggerSync } from '@/api/client';
import { useDashboardData } from '@/features/dashboard/data/queries';
import { ApiErrorNotice } from '@/components/ApiErrorNotice';
import { StatCard } from '@/features/dashboard/components/StatCard';
import { RegistrationsChart } from '@/features/dashboard/components/RegistrationsChart';
import { FleetHealth } from '@/features/dashboard/components/FleetHealth';
import { ValidationMethods } from '@/features/dashboard/components/ValidationMethods';
import { ActivityTable } from '@/features/dashboard/components/ActivityTable';
import { QuickActions } from '@/features/dashboard/components/QuickActions';
import '@/features/dashboard/dashboard-theme.css';

export function DashboardPage() {
  const { data, isLoading, error, refetch, isFetching } = useDashboardData();
  const [syncing, setSyncing] = useState(false);

  // Refresh = pull the inventory from the CA, then refetch. A sync failure
  // (CA unreachable) must not block the refetch of what is already local.
  const handleRefresh = async () => {
    setSyncing(true);
    try {
      await triggerSync();
    } catch {
      // Sync errors surface in the service log; still refetch below.
    } finally {
      setSyncing(false);
    }
    refetch();
  };

  if (error) {
    return <ApiErrorNotice error={error} title="Failed to load the dashboard" />;
  }

  const valueOf = (key: string) => data?.stats.find((s) => s.key === key)?.value ?? 0;

  return (
    <div className="md-dashboard">
      {/* page header */}
      <div className="mb-[18px] flex items-end justify-between gap-3">
        <div>
          <h1 className="text-2xl font-bold text-slate-900 dark:text-slate-100">Dashboard</h1>
          <p className="text-sm text-slate-500 mt-1">Certificate inventory overview from your ADCS CA</p>
        </div>
        <button
          type="button"
          onClick={handleRefresh}
          className="inline-flex items-center gap-2 rounded-lg border border-slate-200 bg-white px-3.5 py-2 text-sm font-semibold text-slate-700 transition-colors hover:bg-slate-50 disabled:opacity-60"
          disabled={syncing || isFetching}
        >
          <RefreshCw className={`h-4 w-4 ${syncing || isFetching ? 'animate-spin' : ''}`} />
          Refresh
        </button>
      </div>

      {isLoading || !data ? (
        <div className="flex items-center justify-center rounded-2xl border border-slate-200 bg-white py-24 text-sm text-slate-500">
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
                issued={valueOf('issued')}
                expiring={valueOf('expiring')}
                expired={valueOf('expired')}
                revoked={valueOf('revoked')}
              />
            </div>
          </div>
        </div>
      )}
    </div>
  );
}
