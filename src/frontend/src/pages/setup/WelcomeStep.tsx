import { Shield, Server, Globe, Bell } from 'lucide-react';

export function WelcomeStep() {
  return (
    <div className="space-y-6">
      <div>
        <h2 className="text-xl font-bold text-slate-900">Welcome to Ducks in a Row</h2>
        <p className="text-sm text-slate-500 mt-1">
          This wizard will guide you through connecting Ducks in a Row to your Active Directory Certificate Services CA.
        </p>
      </div>

      <div className="bg-certus-50 border border-certus-200 rounded-lg p-4">
        <p className="text-sm text-certus-800">
          <strong>What you'll need:</strong>
        </p>
        <ul className="text-sm text-certus-700 mt-2 space-y-1 list-disc list-inside">
          <li>This server must be <strong>domain-joined</strong> (DCOM requires AD authentication)</li>
          <li>The CA hostname and name (e.g., <code className="bg-certus-100 px-1 rounded">ca-server\Contoso-CA</code>)</li>
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

      <p className="text-xs text-slate-400 mt-4">
        Setup typically takes less than 5 minutes. Click <strong>Next</strong> to begin.
      </p>
    </div>
  );
}

function FeatureCard({ icon, title, description }: { icon: React.ReactNode; title: string; description: string }) {
  return (
    <div className="flex items-start gap-3 p-3 rounded-lg border border-slate-100 bg-slate-50">
      <div className="p-2 rounded-md bg-white text-certus-600 shadow-sm">{icon}</div>
      <div>
        <h3 className="text-sm font-semibold text-slate-900">{title}</h3>
        <p className="text-xs text-slate-500 mt-0.5">{description}</p>
      </div>
    </div>
  );
}
