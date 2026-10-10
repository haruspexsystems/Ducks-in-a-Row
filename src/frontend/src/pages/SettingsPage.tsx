import { useQuery } from '@tanstack/react-query';
import { ExternalLink, Mail } from 'lucide-react';
import { DuckMark } from '@/features/dashboard/components/DuckMark';
import { fetchSystemInfo } from '@/api/settings';
import { FEEDBACK_MAILTO, SUPPORT_GITHUB_URL } from '@/lib/support';
import { ExternalUrlCard } from './settings/ExternalUrlCard';
import { AllowedDomainsCard } from './settings/AllowedDomainsCard';
import { RevocationScopeCard } from './settings/RevocationScopeCard';
import { AlertsCard } from './settings/AlertsCard';
import { CaCertificatesCard } from './settings/CaCertificatesCard';
import { CrlStatusCard } from './settings/CrlStatusCard';
import { ServiceRightsCard } from './settings/ServiceRightsCard';

export function SettingsPage() {
  const { data: systemInfo } = useQuery({
    queryKey: ['settings', 'info'],
    queryFn: fetchSystemInfo,
    staleTime: 60_000,
    retry: false,
  });

  return (
    <div className="space-y-8">
      <div>
        <h1 className="text-2xl font-bold text-ink">Settings</h1>
        <p className="text-sm text-muted mt-1">
          Ducks in a Row configuration and system information
        </p>
      </div>

      <div className="bg-surface border border-hairline rounded-lg p-6 space-y-4">
        <div className="flex items-center gap-3">
          <DuckMark size={32} />
          <div>
            <h2 className="text-lg font-semibold text-ink">Ducks in a Row</h2>
            <p className="text-sm text-muted">ACME-to-ADCS Certificate Proxy</p>
          </div>
        </div>

        <div className="border-t border-hairline-soft pt-4">
          <dl className="grid grid-cols-1 sm:grid-cols-2 gap-4">
            <div>
              <dt className="text-sm font-medium text-muted">Version</dt>
              <dd className="text-sm text-ink mt-0.5">{systemInfo?.version ?? '—'}</dd>
            </div>
            <div>
              <dt className="text-sm font-medium text-muted">License</dt>
              <dd className="text-sm text-ink mt-0.5">Open Core (Free Tier)</dd>
            </div>
            {/*
              Issue #112. Only shown when the build carried a commit stamp; a
              build from the release source snapshot has no .git to resolve one
              and legitimately reports null. Rendered in full rather than
              shortened because the whole point is that support can ask an
              operator to copy it out of here.
            */}
            {systemInfo?.commit && (
              <div className="sm:col-span-2">
                <dt className="text-sm font-medium text-muted">Commit</dt>
                <dd className="text-xs font-mono text-ink mt-0.5 break-all">
                  {systemInfo.commit}
                </dd>
              </div>
            )}
          </dl>
        </div>

        <div className="border-t border-hairline-soft pt-4 flex items-center gap-4">
          <a
            href={SUPPORT_GITHUB_URL}
            target="_blank"
            rel="noopener noreferrer"
            className="inline-flex items-center gap-1.5 text-sm text-certus-600 hover:text-certus-800 dark:text-certus-300"
          >
            <ExternalLink className="h-4 w-4" />
            View on GitHub
          </a>
          <a
            href={FEEDBACK_MAILTO}
            className="inline-flex items-center gap-1.5 text-sm text-certus-600 hover:text-certus-800 dark:text-certus-300"
          >
            <Mail className="h-4 w-4" />
            Send feedback
          </a>
        </div>
      </div>

      <ExternalUrlCard />

      <AllowedDomainsCard />

      <RevocationScopeCard />

      <AlertsCard />

      <CaCertificatesCard />

      <ServiceRightsCard />

      <CrlStatusCard />
    </div>
  );
}
