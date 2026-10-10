import { Shield, Server, Globe, Bell } from 'lucide-react';

export function WelcomeStep() {
  return (
    <div className="space-y-6">
      <div>
        <h2 className="text-xl font-bold text-ink">Welcome to Ducks in a Row</h2>
        <p className="text-sm text-muted mt-1">
          This wizard will guide you through connecting Ducks in a Row to your Active Directory Certificate Services CA.
        </p>
      </div>

      <div className="bg-certus-50 dark:bg-certus-500/10 border border-certus-200 dark:border-certus-500/30 rounded-lg p-4">
        <p className="text-sm text-certus-800 dark:text-certus-300">
          <strong>What you'll need:</strong>
        </p>
        <ul className="text-sm text-certus-700 dark:text-certus-300 mt-2 space-y-1 list-disc list-inside">
          <li>This server must be <strong>domain-joined</strong> (DCOM requires AD authentication)</li>
          <li>The CA hostname and name (e.g., <code className="bg-certus-100 dark:bg-certus-500/15 px-1 rounded">ca-server\Example-CA</code>)</li>
          <li>Network access from this server to the CA (RPC/DCOM ports)</li>
          <li>The URL that ACME clients will use to reach this server</li>
        </ul>
      </div>

      <div className="grid grid-cols-1 sm:grid-cols-2 gap-4 mt-6">
        <FeatureCard
          icon={<Server className="h-5 w-5" />}
          title="Connect to ADCS"
          description="Discover and connect to your enterprise Certificate Authority"
        />
        <FeatureCard
          icon={<Shield className="h-5 w-5" />}
          title="Select Templates"
          description="Choose which certificate templates to expose via ACME"
        />
        <FeatureCard
          icon={<Globe className="h-5 w-5" />}
          title="Configure ACME"
          description="Set up the external URL for ACME client access"
        />
        <FeatureCard
          icon={<Bell className="h-5 w-5" />}
          title="Start Issuing"
          description="Any ACME client can request certificates immediately"
        />
      </div>

      <p className="text-xs text-faint mt-4">
        Setup takes about five minutes of clicking once the approvals are in place. The approvals
        are the rights this server's computer account needs on the CA and its templates, and they
        are usually the lead time, so ask for them first. Click <strong>Next</strong> to begin.
      </p>
    </div>
  );
}

function FeatureCard({ icon, title, description }: { icon: React.ReactNode; title: string; description: string }) {
  return (
    <div className="flex items-start gap-3 p-3 rounded-lg border border-hairline-soft bg-sunken">
      <div className="p-2 rounded-md bg-surface text-certus-600 shadow-sm">{icon}</div>
      <div>
        <h3 className="text-sm font-semibold text-ink">{title}</h3>
        <p className="text-xs text-muted mt-0.5">{description}</p>
      </div>
    </div>
  );
}
