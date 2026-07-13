import { useParams, Link } from 'react-router-dom';
import { ArrowLeft, Copy, CheckCircle2 } from 'lucide-react';
import { useEffect, useRef, useState } from 'react';
import { useCertificate } from '@/hooks/useCertificates';
import { certificateDisplayName, formatDateTime, daysUntilExpiry, getExpiryState, isRevoked, revocationReasonLabel } from '@/types';
import { StatusBadge, ExpiryBadge } from '@/components/StatusBadge';

export function CertificateDetailPage() {
  const { id } = useParams<{ id: string }>();
  const certId = parseInt(id ?? '0', 10);
  const { data: cert, isLoading, error } = useCertificate(certId);

  if (isLoading) {
    return (
      <div className="flex items-center justify-center py-20">
        <div className="animate-pulse text-slate-400">Loading certificate details...</div>
      </div>
    );
  }

  if (error || !cert) {
    return (
      <div className="space-y-4">
        <Link to="/certificates" className="inline-flex items-center gap-1 text-sm text-certus-600 hover:text-certus-800">
          <ArrowLeft className="h-4 w-4" />
          Back to certificates
        </Link>
        <div className="bg-red-50 border border-red-200 rounded-lg p-6 text-red-700">
          <h2 className="text-lg font-semibold">Certificate not found</h2>
          <p className="text-sm mt-1">The certificate with ID {id} does not exist.</p>
        </div>
      </div>
    );
  }

  const days = daysUntilExpiry(cert.notAfter);
  const expiryState = getExpiryState(cert.notAfter);
  const revoked = isRevoked(cert);
  const revocationReason = revocationReasonLabel(cert.revokedReason);

  // Fraction of the certificate's real lifetime still remaining (clamped 0 to 100),
  // so the bar reflects multi-year and short-lived certs instead of assuming one year.
  const validFrom = new Date(cert.notBefore).getTime();
  const validTo = new Date(cert.notAfter).getTime();
  const lifetime = validTo - validFrom;
  const remainingPct = lifetime > 0 ? Math.max(0, Math.min(100, ((validTo - Date.now()) / lifetime) * 100)) : 0;

  const expiryBarColor = {
    valid: 'bg-emerald-500',
    'expiring-soon': 'bg-amber-500',
    expired: 'bg-red-500',
  }[expiryState];

  return (
    <div className="space-y-6">
      {/* Back link */}
      <Link
        to="/certificates"
        className="inline-flex items-center gap-1 text-sm text-certus-600 hover:text-certus-800"
      >
        <ArrowLeft className="h-4 w-4" />
        Back to certificates
      </Link>

      {/* Header */}
      <div className="flex items-start justify-between">
        <div>
          <h1 className="text-2xl font-bold text-slate-900">{certificateDisplayName(cert)}</h1>
          <div className="flex items-center gap-2 mt-2">
            <StatusBadge status={cert.status} />
            {!revoked && <ExpiryBadge notAfter={cert.notAfter} />}
            <span className="text-sm text-slate-500">
              Request ID: {cert.requestId}
            </span>
          </div>
        </div>
      </div>

      {/* Expiry bar */}
      <div className="bg-white border border-slate-200 rounded-lg p-4">
        <div className="flex items-center justify-between mb-2">
          <span className="text-sm font-medium text-slate-700">Certificate Validity</span>
          <span className={`text-sm font-semibold ${
            expiryState === 'expired' ? 'text-red-600'
            : expiryState === 'expiring-soon' ? 'text-amber-600'
            : 'text-emerald-600'
          }`}>
            {expiryState === 'expired'
              ? days === 0
                ? 'Expired today'
                : `Expired ${Math.abs(days)} days ago`
              : days === 0
                ? 'Expires today'
                : `${days} days remaining`}
          </span>
        </div>
        <div className="w-full bg-slate-200 rounded-full h-2">
          <div
            className={`h-2 rounded-full transition-all ${expiryBarColor}`}
            style={{ width: `${remainingPct}%` }}
          />
        </div>
        <div className="flex justify-between mt-1 text-xs text-slate-400">
          <span>{formatDateTime(cert.notBefore)}</span>
          <span>{formatDateTime(cert.notAfter)}</span>
        </div>
      </div>

      {/* Detail grid */}
      <div className="grid grid-cols-1 lg:grid-cols-2 gap-6">
        {/* Certificate Info */}
        <div className="bg-white border border-slate-200 rounded-lg">
          <div className="px-4 py-3 border-b border-slate-100">
            <h2 className="text-sm font-semibold text-slate-900">Certificate Information</h2>
          </div>
          <div className="divide-y divide-slate-50">
            <DetailRow label="Serial Number" value={cert.serialNumber} mono copyable />
            <DetailRow label="Subject" value={cert.subject || '—'} />
            {cert.subjectAlternativeNames && (
              <DetailRow label="SANs" value={cert.subjectAlternativeNames} />
            )}
            <DetailRow label="Template" value={cert.templateName} />
            <DetailRow label="Status" value={cert.status} />
            {revoked && (
              <>
                {cert.revokedAt && (
                  <DetailRow label="Revoked" value={formatDateTime(cert.revokedAt)} />
                )}
                {revocationReason && (
                  <DetailRow label="Revocation Reason" value={revocationReason} />
                )}
              </>
            )}
          </div>
        </div>

        {/* Request Info */}
        <div className="bg-white border border-slate-200 rounded-lg">
          <div className="px-4 py-3 border-b border-slate-100">
            <h2 className="text-sm font-semibold text-slate-900">Request Information</h2>
          </div>
          <div className="divide-y divide-slate-50">
            <DetailRow label="Request ID" value={String(cert.requestId)} />
            <DetailRow label="ACME Contact" value={cert.acmeContactEmail ?? '—'} />
            <DetailRow label="CA Requester" value={cert.requestor ?? 'Unknown'} />
            <DetailRow label="Request Date" value={formatDateTime(cert.requestDate)} />
            <DetailRow label="Valid From" value={formatDateTime(cert.notBefore)} />
            <DetailRow label="Valid To" value={formatDateTime(cert.notAfter)} />
            {cert.firstSyncedAt && (
              <DetailRow label="First Synced" value={formatDateTime(cert.firstSyncedAt)} />
            )}
            {cert.lastSyncedAt && (
              <DetailRow label="Last Synced" value={formatDateTime(cert.lastSyncedAt)} />
            )}
          </div>
        </div>
      </div>
    </div>
  );
}

function DetailRow({
  label,
  value,
  mono,
  copyable,
}: {
  label: string;
  value: string;
  mono?: boolean;
  copyable?: boolean;
}) {
  const [copied, setCopied] = useState(false);
  const copyTimer = useRef<ReturnType<typeof setTimeout>>();

  useEffect(() => () => {
    if (copyTimer.current) clearTimeout(copyTimer.current);
  }, []);

  const handleCopy = async () => {
    try {
      if (!navigator.clipboard) throw new Error('Clipboard unavailable');
      await navigator.clipboard.writeText(value);
      setCopied(true);
      if (copyTimer.current) clearTimeout(copyTimer.current);
      copyTimer.current = setTimeout(() => setCopied(false), 2000);
    } catch {
      // Clipboard API is unavailable (non-secure context) or was denied; fail quietly.
    }
  };

  return (
    <div className="flex items-start justify-between px-4 py-3 gap-4">
      <dt className="text-sm text-slate-500 whitespace-nowrap min-w-[120px]">{label}</dt>
      <dd className={`text-sm text-slate-900 text-right break-all ${mono ? 'font-mono text-xs' : ''}`}>
        <span>{value}</span>
        {copyable && (
          <button
            onClick={handleCopy}
            className="ml-2 inline-flex items-center text-slate-400 hover:text-slate-600"
            title="Copy to clipboard"
            aria-label={`Copy ${label}`}
          >
            {copied ? (
              <CheckCircle2 className="h-3.5 w-3.5 text-emerald-500" />
            ) : (
              <Copy className="h-3.5 w-3.5" />
            )}
          </button>
        )}
      </dd>
    </div>
  );
}
