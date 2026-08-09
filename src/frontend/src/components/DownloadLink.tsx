import { Download } from 'lucide-react';

/**
 * A file download rendered as a plain anchor, shared by the CA trust anchor
 * downloads in Settings and the single certificate download on the certificate
 * detail page.
 *
 * An anchor and not a fetch on purpose. Every download endpoint behind this is
 * a GET, so the browser negotiates Windows Integrated Authentication itself and
 * the CSRF header guard does not apply, which a fetch driven download would
 * have to reproduce by hand. It also lets the browser name and save the file
 * from the Content-Disposition header rather than the page building a blob URL.
 */
export function DownloadLink({ href, label }: { href: string; label: string }) {
  return (
    <a
      href={href}
      className="inline-flex items-center gap-1.5 px-2.5 py-1 text-xs font-semibold
                 text-certus-700 dark:text-certus-300 bg-certus-50 dark:bg-certus-500/10 border border-certus-200 dark:border-certus-500/30 rounded-lg
                 hover:bg-certus-100 dark:bg-certus-500/15 transition-colors"
    >
      <Download className="h-3 w-3" />
      {label}
    </a>
  );
}
