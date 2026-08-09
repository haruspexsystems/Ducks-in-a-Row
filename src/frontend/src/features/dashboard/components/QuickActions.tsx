import { Link } from 'react-router-dom';
import { card, cardHover, mono, textInk, textInkSoft, textMuted, textFaint, cn } from '../lib/ui';
import { STATUS, ACCENT, alpha } from '../lib/colors';
import { useIsDark } from '../lib/useIsDark';
import { List, TriangleAlert, Ban, Clock, ArrowRight, type LucideIcon } from 'lucide-react';

interface QuickActionsProps {
  total: number;
  expiring: number;
  expired: number;
  revoked: number;
  /** The operator's "expiring soon" window in days (issue #152). */
  warningDays: number;
}

interface QA {
  tone: 'total' | 'warning' | 'danger' | 'revoked';
  Icon: LucideIcon;
  title: string;
  sub: string;
  big: number | null;
  to: string;
}

export function QuickActions({ total, expiring, expired, revoked, warningDays }: QuickActionsProps) {
  const dark = useIsDark();

  // Deep links into the certificate list's state chips (issue #155). These used
  // to be a pair of timestamps computed here, which had two problems: a shared
  // or bookmarked link froze "now", so an "expiring soon" link slid into the
  // past and began returning expired certificates; and filtering on the expiry
  // date alone also returned revoked certificates that happened to be past
  // their NotAfter, which the card beside it never counted. The symbolic name
  // resolves on the server against the same predicate the card is counted
  // with, so the number and the rows behind it now always agree.
  //
  // warningDays is still the caption's, not the filter's: the server owns the
  // window (issue #152).
  const cards: QA[] = [
    { tone: 'total',   Icon: List,          title: 'View Certificates', sub: `${total.toLocaleString()} total · browse all`, big: null,     to: '/certificates' },
    { tone: 'warning', Icon: TriangleAlert, title: 'Expiring Soon',     sub: `Review within ${warningDays} days`,            big: expiring, to: '/certificates?state=expiring' },
    { tone: 'danger',  Icon: Clock,         title: 'Expired',           sub: 'Past expiration date',                         big: expired,  to: '/certificates?state=expired' },
    { tone: 'revoked', Icon: Ban,           title: 'Revoked',           sub: 'Revoked by the CA',                            big: revoked,  to: '/certificates?state=revoked' },
  ];

  return (
    <div className="flex flex-col gap-[18px]">
      {cards.map((q) => {
        const c = STATUS[q.tone].solid;
        const tinted = q.tone !== 'total';
        return (
          <Link
            key={q.tone}
            to={q.to}
            className={cn(
              'group flex items-center gap-3.5 rounded-2xl border px-[18px] py-4 text-left',
              cardHover,
              tinted ? '' : card,
            )}
            style={
              tinted
                ? { background: alpha(c, dark ? 0.13 : 0.08), borderColor: alpha(c, dark ? 0.4 : 0.3) }
                : undefined
            }
          >
            <span
              className="grid h-[42px] w-[42px] shrink-0 place-items-center rounded-xl"
              style={{
                background: tinted ? alpha(c, dark ? 0.22 : 0.16) : alpha(ACCENT, 0.16),
                color: tinted ? c : ACCENT,
              }}
            >
              <q.Icon size={21} strokeWidth={2.1} />
            </span>

            <div className="flex min-w-0 flex-1 items-center gap-2.5">
              {q.big != null && (
                <span className={cn(mono, 'shrink-0 text-[23px] font-bold leading-none')} style={{ color: c }}>
                  {q.big}
                </span>
              )}
              <div className="min-w-0">
                <div className={cn('text-[14.5px] font-bold leading-tight', textInk)}>{q.title}</div>
                <div className={cn('mt-0.5 text-[12.5px] leading-snug', tinted ? textInkSoft : textMuted)}>{q.sub}</div>
              </div>
            </div>

            <span
              className="shrink-0 transition-transform duration-200 group-hover:translate-x-1"
              style={{ color: tinted ? c : undefined }}
            >
              <ArrowRight size={19} className={tinted ? undefined : cn(textFaint)} />
            </span>
          </Link>
        );
      })}
    </div>
  );
}
