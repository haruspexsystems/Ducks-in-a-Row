import { useQuery } from '@tanstack/react-query';
import { AlertTriangle, Landmark, Loader2 } from 'lucide-react';
import { fetchCaCertificates, type CaCertificateSummary } from '@/api/settings';
import { ApiError } from '@/api/client';
import { DownloadLink } from '@/components/DownloadLink';
import { extractCN } from '@/types';

/**
 * Settings card listing the connected CA's signing certificate chain with
 * per certificate DER and PEM downloads plus PEM and PKCS#7 chain bundles.
 * Downloads are plain anchors: the endpoints are GET, admin authenticated
 * through the ambient Negotiate credentials the browser already sends.
 */
export function CaCertificatesCard() {
  const { data: certificates, isLoading, error } = useQuery({
    queryKey: ['settings', 'ca-certificates'],
    queryFn: fetchCaCertificates,
    staleTime: 300_000,
    retry: false,
  });

  const caUnavailable = error instanceof ApiError && error.status === 503;

  return (
    <div className="bg-surface border border-hairline rounded-lg p-6 space-y-4">
      <div className="flex items-center gap-2">
        <Landmark className="h-4 w-4 text-certus-600" />
        <h3 className="text-sm font-semibold text-ink">CA Certificates</h3>
      </div>
      <p className="text-sm text-muted">
        The certificate chain of the connected CA. Install these in the trust
        stores of machines that request certificates, so they trust what the CA
        issues. The .p7b bundle is what the Windows certificate import wizard
        and Group Policy expect.
      </p>

      {isLoading && (
        <div className="flex items-center gap-2 text-sm text-faint py-2">
          <Loader2 className="h-4 w-4 animate-spin" />
          Loading the CA certificate chain…
        </div>
      )}

      {!isLoading && error != null && (
        <div className="bg-red-50 dark:bg-red-500/10 border border-red-200 dark:border-red-500/30 rounded-lg p-3 flex items-start gap-2">
          <AlertTriangle className="h-4 w-4 text-red-500 mt-0.5" />
          <p className="text-xs text-red-700 dark:text-red-300">
            {caUnavailable
              ? 'The certificate authority is unavailable. Try again shortly.'
              : 'The CA certificate chain could not be loaded. Check the service log.'}
          </p>
        </div>
      )}

      {!isLoading && !error && certificates && certificates.length === 0 && (
        <p className="text-xs text-muted">The CA reported no certificates.</p>
      )}

      {!isLoading && !error && certificates && certificates.length > 0 && (
        <>
          <ul className="divide-y divide-hairline-soft">
            {certificates.map((certificate) => (
              <CertificateRow key={certificate.thumbprint} certificate={certificate} />
            ))}
          </ul>

          <div className="border-t border-hairline-soft pt-3 flex flex-wrap items-center gap-3">
            <span className="text-xs text-muted">Download the full chain:</span>
            <DownloadLink href="/api/settings/ca-certificates/chain/pem" label="PEM bundle" />
            <DownloadLink href="/api/settings/ca-certificates/chain/p7b" label="PKCS#7 (.p7b)" />
          </div>
        </>
      )}
    </div>
  );
}

const roleBadge: Record<CaCertificateSummary['role'], { label: string; classes: string }> = {
  root: { label: 'Root', classes: 'bg-certus-50 dark:bg-certus-500/10 text-certus-700 dark:text-certus-300 border-certus-200 dark:border-certus-500/30' },
  issuing: { label: 'Issuing CA', classes: 'bg-emerald-50 dark:bg-emerald-500/10 text-emerald-700 dark:text-emerald-300 border-emerald-200 dark:border-emerald-500/30' },
  intermediate: { label: 'Intermediate', classes: 'bg-sunken text-ink-mid border-hairline' },
};

function CertificateRow({ certificate }: { certificate: CaCertificateSummary }) {
  const badge = roleBadge[certificate.role] ?? roleBadge.intermediate;

  // Read the name through the shared reader rather than splitting on the first
  // comma (issue #294). These subjects are X509Certificate2.Subject, the Windows
  // CertNameToStr display form, so a certification authority whose common name
  // carries a comma arrives with the whole value quoted: the local split showed
  // CN="Corp, Inc CA", O=Example as "Corp, and it missed a common name that was
  // not first in the subject. extractCN falls back to the whole subject, which
  // is the right answer for a certificate that carries no common name at all.
  const cn = extractCN(certificate.subject);
  const remaining = describeRemaining(certificate.notAfter);

  return (
    <li className="py-3 flex flex-wrap items-center gap-3">
      <div className="flex-1 min-w-0">
        <div className="flex items-center gap-2">
          <span className="text-sm font-medium text-ink truncate">{cn}</span>
          <span
            className={`text-[10px] font-semibold uppercase tracking-wide border rounded px-1.5 py-0.5 ${badge.classes}`}
          >
            {badge.label}
          </span>
        </div>
        <p className="text-xs text-muted mt-0.5">
          Expires {new Date(certificate.notAfter).toLocaleDateString()}
          <span className={`ml-1.5 ${remaining.classes}`}>{remaining.label}</span>
          <span className="mx-1.5">·</span>
          <span className="font-mono">{certificate.thumbprint.slice(0, 16)}…</span>
        </p>
      </div>
      <div className="flex items-center gap-2">
        <DownloadLink
          href={`/api/settings/ca-certificates/${certificate.thumbprint}/der`}
          label="DER (.cer)"
        />
        <DownloadLink
          href={`/api/settings/ca-certificates/${certificate.thumbprint}/pem`}
          label="PEM"
        />
      </div>
    </li>
  );
}

/**
 * How long a CA certificate has left (issue #447).
 *
 * The thresholds are wider than a leaf's on purpose. ADCS never issues a
 * certificate that outlives its own CA certificate, so as one runs down the
 * certificates it issues quietly shrink to match, and Microsoft's own guidance
 * is to renew a CA at half its lifetime. A year of warning is the point at
 * which that starts to matter; ninety days is late.
 */
function describeRemaining(notAfter: string): { label: string; classes: string } {
  const days = Math.floor((new Date(notAfter).getTime() - Date.now()) / 86_400_000);

  if (days <= 0) return { label: '(expired)', classes: 'text-red-600 dark:text-red-400' };
  if (days <= 90) return { label: `(${days} days left)`, classes: 'text-red-600 dark:text-red-400' };
  if (days <= 365) return { label: `(${days} days left)`, classes: 'text-amber-600 dark:text-amber-400' };
  return { label: `(${Math.floor(days / 365)} years left)`, classes: 'text-faint' };
}
