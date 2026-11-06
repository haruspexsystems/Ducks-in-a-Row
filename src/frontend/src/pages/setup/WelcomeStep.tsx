import { Shield, Server, Globe, Bell, ListChecks, ScrollText } from 'lucide-react';

interface Feature {
  icon: React.ReactNode;
  title: string;
  description: string;
}

const issuingFeatures: Feature[] = [
  {
    icon: <Server className="h-5 w-5" />,
    title: 'Connect to ADCS',
    description: 'Discover and connect to your enterprise Certificate Authority',
  },
  {
    icon: <Shield className="h-5 w-5" />,
    title: 'Select Templates',
    description: 'Choose which certificate templates to expose via ACME',
  },
  {
    icon: <Globe className="h-5 w-5" />,
    title: 'Configure ACME',
    description: 'Set up the external URL for ACME client access',
  },
  {
    icon: <Bell className="h-5 w-5" />,
    title: 'Start Issuing',
    description: 'Any ACME client can request certificates immediately',
  },
];

const monitorFeatures: Feature[] = [
  {
    icon: <Server className="h-5 w-5" />,
    title: 'Connect to ADCS',
    description: 'Discover and connect to your enterprise Certificate Authority',
  },
  {
    icon: <ListChecks className="h-5 w-5" />,
    title: 'Watch the inventory',
    description: 'Every certificate the CA has issued, synced and searchable',
  },
  {
    icon: <Bell className="h-5 w-5" />,
    title: 'Expiry alerts',
    description: 'Email or a webhook before a certificate expires',
  },
  {
    icon: <ScrollText className="h-5 w-5" />,
    title: 'CRL watching',
    description: 'A warning before a revocation list goes stale',
  },
];

/**
 * The first step. In monitor mode (issue #471) the cards describe watching a CA
 * rather than issuing from it, and the rights it asks for are the read only ones.
 */
export function WelcomeStep({ monitorMode }: { monitorMode: boolean }) {
  const features = monitorMode ? monitorFeatures : issuingFeatures;
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
          <li>
            {monitorMode
              ? 'The address you will open the Ducks in a Row dashboard at'
              : 'The URL that ACME clients will use to reach this server'}
          </li>
        </ul>
      </div>

      <div className="grid grid-cols-1 sm:grid-cols-2 gap-4 mt-6">
        {features.map((feature) => (
          <FeatureCard key={feature.title} {...feature} />
        ))}
      </div>

      {monitorMode ? (
        <p className="text-xs text-faint mt-4">
          This server runs in <strong>monitor mode</strong>: it reads from the CA and never issues
          or revokes. Its computer account needs Read on the CA, plus Request Certificates, which a
          default CA already grants. Setup takes about five minutes once Read is in place.
          Click <strong>Next</strong> to begin.
        </p>
      ) : (
        <p className="text-xs text-faint mt-4">
          Setup takes about five minutes of clicking once the approvals are in place. The approvals
          are the rights this server's computer account needs on the CA and its templates, and they
          are usually the lead time, so ask for them first. Click <strong>Next</strong> to begin.
        </p>
      )}
    </div>
  );
}

function FeatureCard({ icon, title, description }: Feature) {
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
