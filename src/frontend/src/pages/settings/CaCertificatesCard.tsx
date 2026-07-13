import { useQuery } from '@tanstack/react-query';
import { AlertTriangle, Download, Landmark, Loader2 } from 'lucide-react';
import { fetchCaCertificates, type CaCertificateSummary } from '@/api/settings';
import { ApiError } from '@/api/client';

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
    <div className="bg-white border border-slate-200 rounded-lg p-6 space-y-4">
      <div className="flex items-center gap-2">
        <Landmark className="h-4 w-4 text-certus-600" />
        <h3 className="text-sm font-semibold text-slate-900">CA Certificates</h3>
      </div>
      <p className="text-sm text-slate-500">
        The certificate chain of the connected CA. Install these in the trust
        stores of machines that request certificates, so they trust what the CA
        issues. The .p7b bundle is what the Windows certificate import wizard
        and Group Policy expect.
      </p>

      {isLoading && (
        <div className="flex items-center gap-2 text-sm text-slate-400 py-2">
          <Loader2 className="h-4 w-4 animate-spin" />
          Loading the CA certificate chain…
        </div>
      )}

      {!isLoading && error != null && (
        <div className="bg-red-50 border border-red-200 rounded-lg p-3 flex items-start gap-2">
          <AlertTriangle className="h-4 w-4 text-red-500 mt-0.5" />
          <p className="text-xs text-red-700">
            {caUnavailable
              ? 'The certificate authority is unavailable. Try again shortly.'
              : 'The CA certificate chain could not be loaded. Check the service log.'}
          </p>
        </div>
      )}

      {!isLoading && !error && certificates && certificates.length === 0 && (
        <p className="text-xs text-slate-500">The CA reported no certificates.</p>
      )}

      {!isLoading && !error && certificates && certificates.length > 0 && (
        <>
          <ul className="divide-y divide-slate-100">
            {certificates.map((certificate) => (
              <CertificateRow key={certificate.thumbprint} certificate={certificate} />
            ))}
          </ul>

          <div className="border-t border-slate-100 pt-3 flex flex-wrap items-center gap-3">
            <span className="text-xs text-slate-500">Download the full chain:</span>
            <DownloadLink href="/api/settings/ca-certificates/chain/pem" label="PEM bundle" />
            <DownloadLink href="/api/settings/ca-certificates/chain/p7b" label="PKCS#7 (.p7b)" />
          </div>
        </>
      )}
    </div>
  );
}

const roleBadge: Record<CaCertificateSummary['role'], { label: string; classes: string }> = {
  root: { label: 'Root', classes: 'bg-certus-50 text-certus-700 border-certus-200' },
  issuing: { label: 'Issuing CA', classes: 'bg-emerald-50 text-emerald-700 border-emerald-200' },
  intermediate: { label: 'Intermediate', classes: 'bg-slate-50 text-slate-600 border-slate-200' },
};

function CertificateRow({ certificate }: { certificate: CaCertificateSummary }) {
  const badge = roleBadge[certificate.role] ?? roleBadge.intermediate;
  const cn = certificate.subject.replace(/^CN=/i, '').split(',')[0];

  return (
    <li className="py-3 flex flex-wrap items-center gap-3">
      <div className="flex-1 min-w-0">
        <div className="flex items-center gap-2">
          <span className="text-sm font-medium text-slate-900 truncate">{cn}</span>
          <span
            className={`text-[10px] font-semibold uppercase tracking-wide border rounded px-1.5 py-0.5 ${badge.classes}`}
          >
            {badge.label}
          </span>
        </div>
        <p className="text-xs text-slate-500 mt-0.5">
          Expires {new Date(certificate.notAfter).toLocaleDateString()}
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

function DownloadLink({ href, label }: { href: string; label: string }) {
  return (
    <a
      href={href}
      className="inline-flex items-center gap-1.5 px-2.5 py-1 text-xs font-semibold
                 text-certus-700 bg-certus-50 border border-certus-200 rounded-lg
                 hover:bg-certus-100 transition-colors"
    >
      <Download className="h-3 w-3" />
      {label}
    </a>
  );
}
