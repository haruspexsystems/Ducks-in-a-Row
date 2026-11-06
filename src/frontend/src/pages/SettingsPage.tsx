import { AlertTriangle, BellRing, CalendarClock, ExternalLink, Mail } from 'lucide-react';
import { DuckMark } from '@/features/dashboard/components/DuckMark';
import { ReleaseNotice } from '@/components/ReleaseNotice';
import { SecurityNotices } from '@/components/SecurityNotices';
import { useLicence } from '@/hooks/useLicence';
import { useSystemInfo } from '@/hooks/useSystemInfo';
import { aboutTier } from '@/lib/licence';
import { describeOutdatedRelease, describeReleaseAge, formatReleaseDate } from '@/lib/releaseAge';
import { FEEDBACK_MAILTO, RELEASES_URL, SUPPORT_GITHUB_URL } from '@/lib/support';
import { ExternalUrlCard } from './settings/ExternalUrlCard';
import { AllowedDomainsCard } from './settings/AllowedDomainsCard';
import { RevocationScopeCard } from './settings/RevocationScopeCard';
import { AlertsCard } from './settings/AlertsCard';
import { CaCertificatesCard } from './settings/CaCertificatesCard';
import { CrlStatusCard } from './settings/CrlStatusCard';
import { ServiceRightsCard } from './settings/ServiceRightsCard';
import { LicenceCard } from './settings/LicenceCard';

export function SettingsPage() {
  const { data: systemInfo } = useSystemInfo();
  // Issue #470: only once the server has said so; until then full mode as ever.
  const monitorMode = systemInfo?.mode === 'monitor';
  const { data: licence } = useLicence();

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
            {/*
              Issue #623. The date of the commit the build was stamped from,
              with its age by the server's clock. Hidden like the commit row
              when the build carried no stamp.
            */}
            {systemInfo?.commitDate && (
              <div>
                <dt className="text-sm font-medium text-muted">Released</dt>
                <dd className="text-sm text-ink mt-0.5">
                  {formatReleaseDate(systemInfo.commitDate)}
                  {systemInfo.releaseAgeDays != null && (
                    <span className="text-muted"> ({describeReleaseAge(systemInfo.releaseAgeDays)})</span>
                  )}
                </dd>
              </div>
            )}
            {/* Issue #493: the live tier, from the same status the licence card reads. */}
            <div>
              <dt className="text-sm font-medium text-muted">Licence</dt>
              <dd className="text-sm text-ink mt-0.5">{aboutTier(licence) ?? '—'}</dd>
            </div>
            {/* Issue #470. Set by a local administrator on the server, never here. */}
            <div>
              <dt className="text-sm font-medium text-muted">Mode</dt>
              <dd className="text-sm text-ink mt-0.5">
                {systemInfo
                  ? monitorMode
                    ? 'Monitor: watches the CA, never issues or revokes'
                    : 'Full: issuance and revocation'
                  : '—'}
              </dd>
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
            {/*
              Issue #623. The shared frameworks the service runs on. Their
              patches arrive through Windows Update, not through the installer
              (the bundle installs a runtime only when none is present), so an
              operator checking what is current needs both lines.
            */}
            {systemInfo && (
              <div className="sm:col-span-2">
                <dt className="text-sm font-medium text-muted">Runtime</dt>
                <dd className="text-sm text-ink mt-0.5">
                  {systemInfo.runtimeVersion}, ASP.NET Core {systemInfo.aspNetCoreVersion}
                  <span className="block text-xs text-muted mt-0.5">
                    Patched by Windows Update, not by the Ducks in a Row installer.
                  </span>
                </dd>
              </div>
            )}
          </dl>
        </div>

        {/* Issue #623: the one in product aid the no internet rule allows. The
            warning appears once the age passes Certus:ReleaseAgeWarningDays;
            the line under it stays whatever the age is. */}
        <div className="border-t border-hairline-soft pt-4">
          <h3 className="flex items-center gap-2 text-sm font-semibold text-ink mb-1">
            <CalendarClock className="h-4 w-4 text-certus-600 dark:text-certus-300" />
            Updates
          </h3>
          {systemInfo?.releaseOutdated && systemInfo.releaseAgeDays != null && (
            <div
              role="status"
              className="flex items-start gap-2 rounded-md border border-amber-300 bg-amber-50
                         dark:border-amber-500/40 dark:bg-amber-500/10 px-3 py-2 mb-2 text-sm
                         text-amber-900 dark:text-amber-200"
            >
              <AlertTriangle className="h-4 w-4 mt-0.5 shrink-0" />
              <p>
                {describeOutdatedRelease(systemInfo.releaseAgeDays, systemInfo.releaseAgeWarningDays)}{' '}
                <a
                  href={RELEASES_URL}
                  target="_blank"
                  rel="noopener noreferrer"
                  className="underline underline-offset-2 font-medium"
                >
                  See the releases page
                </a>
                .
              </p>
            </div>
          )}
          <ReleaseNotice />
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

        {/* Issue #242: the Setup Complete page offers this once; here it stays
            for an operator who skipped it or inherited the server. */}
        <div className="border-t border-hairline-soft pt-4">
          <h3 className="flex items-center gap-2 text-sm font-semibold text-ink mb-1">
            <BellRing className="h-4 w-4 text-certus-600 dark:text-certus-300" />
            Security notices
          </h3>
          <SecurityNotices />
        </div>
      </div>

      {/* In both modes: the paid tier is not an issuance feature (issue #493). */}
      <LicenceCard />

      <ExternalUrlCard />

      {/* Both govern issuance and revocation, which monitor mode never does
          (issue #470). */}
      {!monitorMode && <AllowedDomainsCard />}

      {!monitorMode && <RevocationScopeCard />}

      <AlertsCard />

      <CaCertificatesCard />

      <ServiceRightsCard />

      <CrlStatusCard />
    </div>
  );
}
