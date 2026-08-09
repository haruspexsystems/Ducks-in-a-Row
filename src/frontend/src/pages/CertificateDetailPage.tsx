import { useParams, Link } from 'react-router-dom';
import { ArrowLeft, Copy, CheckCircle2, ShieldOff } from 'lucide-react';
import { useEffect, useRef, useState } from 'react';
import { useQueryClient } from '@tanstack/react-query';
import { useCertificate } from '@/hooks/useCertificates';
import { syncStatusKey } from '@/hooks/useSyncStatus';
import type { CertificateDetail, CertificateLink } from '@/types';
import { certificateDisplayName, formatDate, formatDateTime, daysUntilExpiry, getExpiryState, isRevoked, revocationReasonLabel, hasCertificate, dispositionTone, formatHResult, keyDescription, signatureAlgorithmLabel, extendedKeyUsages, keyUsageLabels } from '@/types';
import { StatusBadge, ExpiryBadge, RenewalBadge } from '@/components/StatusBadge';
import { CopyButton } from '@/components/CopyButton';
import { DownloadLink } from '@/components/DownloadLink';
import { RevokeCertificateDialog } from '@/components/RevokeCertificateDialog';
import { CertificateAlertHistory } from '@/components/CertificateAlertHistory';
import { certificateAlertsKey } from '@/hooks/useCertificateAlerts';
import { fetchText } from '@/api/client';
import type { RevokeCertificateResult } from '@/api/client';
import { useExpiryWarningDays } from '@/hooks/useExpiryWarningDays';

export function CertificateDetailPage() {
  const { id } = useParams<{ id: string }>();
  const certId = parseInt(id ?? '0', 10);
  const { data: cert, isLoading, error } = useCertificate(certId);
  // Read here rather than beside its use below, because the loading and error
  // branches return before that point and hooks cannot sit behind a condition.
  const warningDays = useExpiryWarningDays();
  const queryClient = useQueryClient();
  const [revokeOpen, setRevokeOpen] = useState(false);
  // Set when a revocation succeeded at the CA but the in request inventory
  // refresh did not, so the page can say why it may still read Issued.
  const [resyncPending, setResyncPending] = useState(false);

  if (isLoading) {
    return (
      <div className="flex items-center justify-center py-20">
        <div className="animate-pulse text-faint">Loading certificate details...</div>
      </div>
    );
  }

  if (error || !cert) {
    return (
      <div className="space-y-4">
        <Link to="/certificates" className="inline-flex items-center gap-1 text-sm text-certus-600 hover:text-certus-800 dark:text-certus-300">
          <ArrowLeft className="h-4 w-4" />
          Back to certificates
        </Link>
        <div className="bg-red-50 dark:bg-red-500/10 border border-red-200 dark:border-red-500/30 rounded-lg p-6 text-red-700 dark:text-red-300">
          <h2 className="text-lg font-semibold">Certificate not found</h2>
          <p className="text-sm mt-1">The certificate with ID {id} does not exist.</p>
        </div>
      </div>
    );
  }

  const days = daysUntilExpiry(cert.notAfter);
  const expiryState = getExpiryState(cert.notAfter, warningDays);
  const revoked = isRevoked(cert);
  const revocationReason = revocationReasonLabel(cert.revokedReason);

  // A pending, denied, or failed request has no certificate behind it, so its
  // validity dates are placeholders. Every expiry affordance is suppressed for
  // those rows; otherwise the page reports a request awaiting approval as
  // having expired several hundred thousand days ago.
  const issuedCertificate = hasCertificate(cert);
  const tone = dispositionTone(cert.status);

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

  // After a revocation the fresh row from the response replaces the cached
  // one, and every surface that counts or lists certificates is invalidated,
  // the sync status header included because the revoke ran a sync.
  //
  // The expiry warnings block is invalidated too, because revoking changes its
  // answer: the certificate stops being monitored the moment its status
  // changes. Without this it keeps saying Ducks is watching this certificate
  // for as long as the cached response stays fresh, directly contradicting the
  // action the reader just took.
  const handleRevoked = (result: RevokeCertificateResult) => {
    setRevokeOpen(false);
    setResyncPending(!result.resynced);
    queryClient.setQueryData(['certificate', certId], result.certificate);
    queryClient.invalidateQueries({ queryKey: ['certificates'] });
    queryClient.invalidateQueries({ queryKey: ['stats'] });
    queryClient.invalidateQueries({ queryKey: syncStatusKey });
    queryClient.invalidateQueries({ queryKey: certificateAlertsKey(certId) });
  };

  return (
    <div className="space-y-6">
      {/* Back link */}
      <Link
        to="/certificates"
        className="inline-flex items-center gap-1 text-sm text-certus-600 hover:text-certus-800 dark:text-certus-300"
      >
        <ArrowLeft className="h-4 w-4" />
        Back to certificates
      </Link>

      {/* Header */}
      <div className="flex items-start justify-between">
        <div>
          <h1 className="text-2xl font-bold text-ink">{certificateDisplayName(cert)}</h1>
          <div className="flex items-center gap-2 mt-2">
            <StatusBadge status={cert.status} />
            {issuedCertificate && !revoked && <ExpiryBadge notAfter={cert.notAfter} />}
            {issuedCertificate && <RenewalBadge issuedByAcme={cert.issuedByAcme} />}
            <span className="text-sm text-muted">
              Request ID: {cert.requestId}
            </span>
          </div>
          {/*
            What the renewal badge above means for the reader, in one sentence
            and sitting directly under it. The ACME wording stops short of
            claiming the client is still running, because the flag only records
            that Ducks issued the certificate.
          */}
          {issuedCertificate && (
            <p className="text-sm text-muted mt-2 max-w-2xl">
              {cert.issuedByAcme
                ? 'Ducks issued this certificate through the ACME proxy, so an ACME client should be renewing it. Ducks cannot confirm that client is still running.'
                : 'This certificate reached the inventory from the CA database and was not issued through Ducks, so nothing here will renew it.'}
            </p>
          )}
        </div>
        {/* The one destructive action on this page. Detail page only, one
            certificate at a time, and never for a row that is already
            revoked or never became a certificate (issue #159). When the
            server refuses the revocation (the detail response and the
            revoke endpoint share one evaluator), the button renders
            disabled with the server's reason rather than hidden: the admin
            should see the action exists and read why it is unavailable. */}
        {issuedCertificate && !revoked && (
          cert.revocationBlocked ? (
            <div className="shrink-0 max-w-xs text-right">
              <button
                disabled
                className="inline-flex items-center gap-1.5 rounded-md border border-hairline-strong px-3 py-2 text-sm font-medium text-muted opacity-60 cursor-not-allowed"
              >
                <ShieldOff className="h-4 w-4" />
                Revoke certificate
              </button>
              <p className="text-xs text-muted mt-1.5">
                {cert.revocationBlockedDetail ??
                  'The server refuses to revoke this certificate.'}
                {cert.revocationBlocked === 'out-of-scope' && (
                  <>
                    {' '}
                    <Link
                      to="/settings"
                      className="text-certus-600 hover:text-certus-800 dark:text-certus-300 font-medium"
                    >
                      Revocation scope settings
                    </Link>
                  </>
                )}
              </p>
            </div>
          ) : (
            <button
              onClick={() => setRevokeOpen(true)}
              className="inline-flex items-center gap-1.5 shrink-0 rounded-md border border-red-300 px-3 py-2 text-sm font-medium text-red-700 dark:text-red-300 hover:bg-red-50 dark:bg-red-500/10"
            >
              <ShieldOff className="h-4 w-4" />
              Revoke certificate
            </button>
          )
        )}
      </div>

      {/* Shown only when the CA revoked but the in request inventory refresh
          failed. The revocation itself is recorded, so the status below is
          right; what is missing is the CA's own account of it. */}
      {resyncPending && (
        <div className="border rounded-lg p-4 bg-amber-50 dark:bg-amber-500/10 border-amber-200 dark:border-amber-500/30" role="alert">
          <p className="text-sm font-semibold text-amber-900 dark:text-amber-200">
            Revoked at the certification authority
          </p>
          <p className="text-sm mt-1 text-amber-800 dark:text-amber-300">
            The inventory refresh after the revocation failed, so the revocation date
            and reason here are the ones Ducks recorded rather than the ones the
            certification authority reports. They are replaced on the next sync.
          </p>
        </div>
      )}

      {/*
        The CA's own account of why this request pended, was denied, or failed.
        Quoted verbatim and attributed, never reworded by Ducks. Rendering is
        driven purely by the field being present: the API populates it only for
        the three request dispositions, so an issued certificate shows nothing
        here without a second condition that could drift out of step.
      */}
      {cert.dispositionMessage && (
        <div className={`border rounded-lg p-4 ${tone.container}`}>
          <p className={`text-sm font-semibold ${tone.heading}`}>
            Reported by the certification authority
          </p>
          <p className={`text-sm mt-1 whitespace-pre-line break-words ${tone.body}`}>
            {cert.dispositionMessage}
          </p>
          {cert.statusCode != null && (
            <p className={`text-xs font-mono mt-2 ${tone.body}`}>
              {formatHResult(cert.statusCode)}
            </p>
          )}
        </div>
      )}

      {/*
        The mirror image of the callout above, and deliberately worded against
        it. That one quotes the CA; this one is Ducks' own guess from matching
        names, so it attributes itself, says plainly what the CA does not know,
        and shows the evidence rather than asking to be believed. Neutral slate
        rather than dispositionTone's amber and red: nothing here needs
        attention, it is context.
      */}
      {(cert.supersededBy || (cert.supersedes && cert.supersedes.length > 0)) && (
        <div className="border rounded-lg p-4 bg-sunken border-hairline">
          <p className="text-sm font-semibold text-ink">
            Matched by Ducks from the certificate names
          </p>
          <p className="text-sm mt-1 text-ink-mid">
            The certification authority does not record renewals, so this is an
            observation, not something it reported. These certificates came from the
            same template and cover the same names, and the later one is treated as
            the replacement. Two teams requesting the same name from the same
            template would look identical here.
          </p>

          <div className="mt-3 space-y-3">
            {cert.supersededBy && (
              <SupersessionEntry label="Superseded by" links={[cert.supersededBy]} />
            )}
            {cert.supersedes && cert.supersedes.length > 0 && (
              <SupersessionEntry label="Supersedes" links={cert.supersedes} />
            )}
            <div>
              <p className="text-xs font-semibold text-muted uppercase tracking-wider">
                Matched on
              </p>
              {/*
                What this certificate carries, which by construction is what the
                match was made on. SANs first and the subject only when there are
                none, because that is the precedence the matching key itself uses.
                Note it is the reverse of certificateDisplayName, which prefers the
                subject CN for a title, so on a certificate carrying both this line
                and the heading above can legitimately read differently.
              */}
              <p className="text-sm text-ink-soft mt-1 break-words">
                {cert.subjectAlternativeNames || cert.subject || '—'}
              </p>
            </div>
          </div>
        </div>
      )}

      {/* Expiry bar. Only meaningful once a certificate exists. */}
      {issuedCertificate && (
      <div className="bg-surface border border-hairline rounded-lg p-4">
        <div className="flex items-center justify-between mb-2">
          <span className="text-sm font-medium text-ink-soft">Certificate Validity</span>
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
        <div className="w-full bg-track rounded-full h-2">
          <div
            className={`h-2 rounded-full transition-all ${expiryBarColor}`}
            style={{ width: `${remainingPct}%` }}
          />
        </div>
        <div className="flex justify-between mt-1 text-xs text-faint">
          <span>{formatDateTime(cert.notBefore)}</span>
          <span>{formatDateTime(cert.notAfter)}</span>
        </div>
      </div>
      )}

      {/* Detail grid */}
      <div className="grid grid-cols-1 lg:grid-cols-2 gap-6">
        {/* Certificate Info */}
        <div className="bg-surface border border-hairline rounded-lg">
          <div className="px-4 py-3 border-b border-hairline-soft">
            <h2 className="text-sm font-semibold text-ink">Certificate Information</h2>
          </div>
          <div className="divide-y divide-hairline-soft">
            {/* A request that never became a certificate has no serial. */}
            {cert.serialNumber
              ? <DetailRow label="Serial Number" value={cert.serialNumber} mono copyable />
              : <DetailRow label="Serial Number" value="—" />}
            {/* On a request that never became a certificate this name came from
                the CSR, so it is what was asked for rather than what was
                signed. Label it so the distinction is on the page rather than
                left for the admin to infer from the status. */}
            <DetailRow
              label={issuedCertificate ? 'Subject' : 'Requested Subject'}
              value={cert.subject || '—'}
            />
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
        <div className="bg-surface border border-hairline rounded-lg">
          <div className="px-4 py-3 border-b border-hairline-soft">
            <h2 className="text-sm font-semibold text-ink">Request Information</h2>
          </div>
          <div className="divide-y divide-hairline-soft">
            <DetailRow label="Request ID" value={String(cert.requestId)} />
            <DetailRow label="ACME Contact" value={cert.acmeContactEmail ?? '—'} />
            <DetailRow label="CA Requester" value={cert.requestor ?? 'Unknown'} />
            <DetailRow label="Request Date" value={formatDateTime(cert.requestDate)} />
            <DetailRow
              label="Valid From"
              value={issuedCertificate ? formatDateTime(cert.notBefore) : '—'}
            />
            <DetailRow
              label="Valid To"
              value={issuedCertificate ? formatDateTime(cert.notAfter) : '—'}
            />
            {cert.firstSyncedAt && (
              <DetailRow label="First Synced" value={formatDateTime(cert.firstSyncedAt)} />
            )}
            {cert.lastSyncedAt && (
              <DetailRow label="Last Synced" value={formatDateTime(cert.lastSyncedAt)} />
            )}
          </div>
        </div>
      </div>

      <CertificateAndKeyCard cert={cert} />

      {/* Whether anybody was actually told this is expiring (issue #160). Gated
          on issuedCertificate like every other expiry affordance on this page:
          a request that never became a certificate has no expiry to warn about.
          A revoked certificate does render, and keeps the warnings it got before
          it was revoked. */}
      {issuedCertificate && <CertificateAlertHistory certificateId={cert.id} />}

      {revokeOpen && (
        <RevokeCertificateDialog
          cert={cert}
          onClose={() => setRevokeOpen(false)}
          onRevoked={handleRevoked}
        />
      )}
    </div>
  );
}

/**
 * What the certificate itself says, and the certificate itself (issue #158):
 * the thumbprint an admin compares against what a host is actually serving, the
 * key and signature detail, and the download.
 *
 * All of it comes from the certificate's own DER, so a row that never had one
 * shows nothing here. The whole card is suppressed in that case rather than
 * rendering a heading over empty labelled fields, and each row inside is
 * suppressed on its own, because a certificate legitimately need not carry an
 * EKU or key usage extension.
 *
 * One certificate, deliberately. There is no bulk export here and none is to be
 * added: handing an admin a certificate they already own is basic certificate
 * management, exporting the inventory is the paid tier.
 */
function CertificateAndKeyCard({ cert }: { cert: CertificateDetail }) {
  // Surfaces only when fetching the PEM for the clipboard fails. A clipboard
  // that is unavailable or denied stays silent inside CopyButton, as it always
  // has; this is the failure the reader cannot otherwise account for.
  const [copyError, setCopyError] = useState<string | null>(null);

  const key = keyDescription(cert.keyAlgorithm, cert.keySizeBits);
  const signature = signatureAlgorithmLabel(cert.signatureAlgorithmOid);
  const ekus = extendedKeyUsages(cert.extendedKeyUsageOids);
  const usages = keyUsageLabels(cert.keyUsage);

  const hasDetail = Boolean(cert.sha256Thumbprint || key || signature || ekus || usages);
  if (!hasDetail && !cert.canDownload) return null;

  return (
    <div className="bg-surface border border-hairline rounded-lg">
      <div className="px-4 py-3 border-b border-hairline-soft flex items-center justify-between gap-4">
        <h2 className="text-sm font-semibold text-ink">Certificate and Key</h2>
        {cert.canDownload && (
          <div className="flex items-center gap-2">
            <DownloadLink href={`/api/certificates/${cert.id}/pem`} label="PEM" />
            <DownloadLink href={`/api/certificates/${cert.id}/der`} label="DER (.cer)" />
            <CopyButton
              label="certificate PEM"
              onError={setCopyError}
              value={() => {
                setCopyError(null);
                return fetchText(`/api/certificates/${cert.id}/pem`);
              }}
            />
          </div>
        )}
      </div>

      {/* alert, not status: the reader pressed a button and it did not do what
          they asked, so a screen reader should say so now rather than wait for
          a pause. */}
      {copyError && (
        <p className="px-4 pt-3 text-xs text-red-600" role="alert">
          {copyError}
        </p>
      )}

      <div className="divide-y divide-hairline-soft">
        {cert.sha256Thumbprint && (
          <DetailRow label="SHA256 Thumbprint" value={cert.sha256Thumbprint} mono copyable />
        )}
        {key && <DetailRow label="Key" value={key} />}
        {signature && <DetailRow label="Signature Algorithm" value={signature} />}
        {ekus && (
          <div className="flex items-start justify-between px-4 py-3 gap-4">
            <dt className="text-sm text-muted whitespace-nowrap min-w-[120px]">
              Extended Key Usage
            </dt>
            <dd className="text-sm text-ink text-right break-all">
              <ul className="space-y-1">
                {ekus.map((eku) => (
                  <li key={eku.oid}>
                    {eku.label}
                    {/* The OID stays visible beside the name: it is what an
                        admin pastes into a search or compares with certutil,
                        and for an OID we have no name for it is all there is. */}
                    {eku.label !== eku.oid && (
                      <span className="ml-2 font-mono text-xs text-faint">{eku.oid}</span>
                    )}
                  </li>
                ))}
              </ul>
            </dd>
          </div>
        )}
        {usages && <DetailRow label="Key Usage" value={usages.join(', ')} />}
      </div>
    </div>
  );
}

/**
 * One direction of the inferred relationship: the other certificate as a link,
 * with the two facts a reader needs to judge the inference. The issue date is
 * half the evidence (the later one is why it is called the replacement), and the
 * requester is what catches the failure mode, which is two teams independently
 * asking for the same name.
 *
 * Takes a list because "supersedes" can legitimately hold more than one: a
 * revoked certificate never supersedes, so one sitting mid lineage leaves itself
 * and its predecessor both pointing at the same successor.
 */
function SupersessionEntry({ label, links }: { label: string; links: CertificateLink[] }) {
  return (
    <div>
      <p className="text-xs font-semibold text-muted uppercase tracking-wider">{label}</p>
      <ul className="mt-1 space-y-1">
        {links.map((link) => (
          <li key={link.id}>
            <Link
              to={`/certificates/${link.id}`}
              className="text-sm font-medium text-certus-700 dark:text-certus-300 hover:text-certus-900 dark:text-certus-200 hover:underline"
            >
              {certificateDisplayName(link)}
            </Link>
            {/* Explicit, so the name and its dates stay separate words when the
                text is copied or read aloud, not only when ml-2 is painted. */}
            {' '}
            <span className="text-xs text-muted">
              issued {formatDate(link.notBefore)}
              {link.requestor ? `, requested by ${link.requestor}` : ''}
            </span>
          </li>
        ))}
      </ul>
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
      <dt className="text-sm text-muted whitespace-nowrap min-w-[120px]">{label}</dt>
      <dd className={`text-sm text-ink text-right break-all ${mono ? 'font-mono text-xs' : ''}`}>
        <span>{value}</span>
        {copyable && (
          <button
            onClick={handleCopy}
            className="ml-2 inline-flex items-center text-faint hover:text-ink-mid"
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
