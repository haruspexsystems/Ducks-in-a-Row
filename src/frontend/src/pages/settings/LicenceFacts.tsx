import type { LicenceDetails } from '@/api/licence';
import { licenceFacts } from '@/lib/licence';

/**
 * The facts of a licence as a definition list: the installed licence on the
 * card, a candidate in the preview, and both side by side when the paid module
 * judges a candidate worse (issue #493). Only a verified licence shows more
 * than this server's forest; nothing an unverified file says is ever shown.
 */
export function LicenceFacts({ licence, title }: { licence: LicenceDetails; title?: string }) {
  const facts = licenceFacts(licence);
  return (
    <div className="space-y-2">
      {title && <h4 className="text-xs font-semibold uppercase tracking-wide text-faint">{title}</h4>}
      <dl className="grid grid-cols-[max-content_1fr] gap-x-4 gap-y-1 text-xs">
        {facts.map((fact) => (
          <div key={fact.label} className="contents">
            <dt className="text-muted">{fact.label}</dt>
            <dd className="text-ink break-all">{fact.value}</dd>
          </div>
        ))}
      </dl>
    </div>
  );
}
