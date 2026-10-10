import { useEffect, useState } from 'react';
import { ShieldAlert } from 'lucide-react';
import type { ServiceRightsReport } from '@/api/serviceRights';
import { ServiceRightsPanel } from '@/components/ServiceRightsReport';
import { needsAcknowledgement, rowsNotProven, statusLabel } from '@/lib/serviceRights';

/**
 * The Review step's rights check (issue #440): the full report for the chosen
 * CA and templates, and, when nothing yet proves the rights, an explicit
 * acknowledgement naming every row that is not proven.
 *
 * It never blocks on a right being missing. An operator may well be collecting
 * the approvals while finishing setup, and a Failed row is theirs to weigh. What
 * it stops is finishing without being told: the wizard used to let the HTTPS
 * enrolment, the one thing that proves anything, be skipped in silence.
 */
export function ServiceRightsAcknowledgement({
  caConnectionString,
  templates,
  onReadyChange,
}: {
  caConnectionString: string;
  templates: string[];
  /** True once the check has answered and anything it could not prove is acknowledged. */
  onReadyChange: (ready: boolean) => void;
}) {
  // undefined while the first check is running; null when it could not run.
  const [report, setReport] = useState<ServiceRightsReport | null | undefined>(undefined);
  const [acknowledged, setAcknowledged] = useState(false);

  const answered = report !== undefined;
  const needed = answered && needsAcknowledgement(report);
  const notProven = report ? rowsNotProven(report) : [];

  // A fresh answer ("Check again") asks again: the list it names may differ.
  useEffect(() => {
    setAcknowledged(false);
  }, [report]);

  useEffect(() => {
    onReadyChange(answered && (!needed || acknowledged));
    // eslint-disable-next-line react-hooks/exhaustive-deps
  }, [answered, needed, acknowledged]);

  return (
    <div className="space-y-3">
      <ServiceRightsPanel
        caConnectionString={caConnectionString}
        templates={templates}
        onReport={setReport}
      />

      {needed && (
        <label className="flex items-start gap-3 rounded-lg border border-amber-200 dark:border-amber-500/30 bg-amber-50 dark:bg-amber-500/10 p-4 cursor-pointer">
          <input
            type="checkbox"
            checked={acknowledged}
            onChange={(e) => setAcknowledged(e.target.checked)}
            className="mt-1 h-4 w-4 text-certus-600 border-hairline-strong rounded focus:ring-certus-500"
          />
          <span className="space-y-2">
            <span className="flex items-center gap-2 text-sm font-semibold text-amber-900 dark:text-amber-200">
              <ShieldAlert className="h-4 w-4 text-amber-600" />
              Complete setup without proof of these
            </span>
            {report === null ? (
              <span className="block text-xs text-amber-800 dark:text-amber-300">
                The rights check did not run, so nothing about this server's rights on the CA is known.
              </span>
            ) : (
              <ul className="text-xs text-amber-800 dark:text-amber-300 space-y-0.5 list-disc list-inside">
                {notProven.map((row) => (
                  <li key={row.id}>
                    {row.title}: {statusLabel(row)}
                  </li>
                ))}
              </ul>
            )}
            <span className="block text-xs text-amber-700 dark:text-amber-300">
              The HTTPS certificate on the External URL step would prove Enroll on the template it
              uses; otherwise the first ACME order from each template is the proof. Setup can finish
              either way.
            </span>
          </span>
        </label>
      )}
    </div>
  );
}
