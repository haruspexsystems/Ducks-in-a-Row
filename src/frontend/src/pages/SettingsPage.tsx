import { useQuery } from '@tanstack/react-query';
import { ExternalLink, Mail } from 'lucide-react';
import { DuckMark } from '@/features/dashboard/components/DuckMark';
import { fetchSystemInfo } from '@/api/settings';
import { ExternalUrlCard } from './settings/ExternalUrlCard';
import { CaCertificatesCard } from './settings/CaCertificatesCard';

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
        <h1 className="text-2xl font-bold text-slate-900">Settings</h1>
        <p className="text-sm text-slate-500 mt-1">
          Ducks in a Row configuration and system information
        </p>
      </div>

      <div className="bg-white border border-slate-200 rounded-lg p-6 space-y-4">
        <div className="flex items-center gap-3">
          <DuckMark size={32} />
          <div>
            <h2 className="text-lg font-semibold text-slate-900">Ducks in a Row</h2>
            <p className="text-sm text-slate-500">ACME-to-ADCS Certificate Proxy</p>
          </div>
        </div>

        <div className="border-t border-slate-100 pt-4">
          <dl className="grid grid-cols-1 sm:grid-cols-2 gap-4">
            <div>
              <dt className="text-sm font-medium text-slate-500">Version</dt>
              <dd className="text-sm text-slate-900 mt-0.5">{systemInfo?.version ?? '—'}</dd>
            </div>
            <div>
              <dt className="text-sm font-medium text-slate-500">License</dt>
              <dd className="text-sm text-slate-900 mt-0.5">Open Core (Free Tier)</dd>
            </div>
          </dl>
        </div>

        <div className="border-t border-gray-100 pt-4 flex items-center gap-4">
          <a
            href="https://github.com/haruspexsystems/Ducks-in-a-Row"
            target="_blank"
            rel="noopener noreferrer"
            className="inline-flex items-center gap-1.5 text-sm text-certus-600 hover:text-certus-800"
          >
            <ExternalLink className="h-4 w-4" />
            View on GitHub
          </a>
          <a
            href="mailto:feedback@haruspex.systems?subject=Ducks%20in%20a%20Row%20feedback"
            className="inline-flex items-center gap-1.5 text-sm text-certus-600 hover:text-certus-800"
          >
            <Mail className="h-4 w-4" />
            Send feedback
          </a>
        </div>
      </div>

      <ExternalUrlCard />

      <CaCertificatesCard />
    </div>
  );
}
