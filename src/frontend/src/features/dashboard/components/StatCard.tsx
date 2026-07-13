import { card, cardHover, cardPad, mono, textMuted, textFaint, cn } from '../lib/ui';
import { STATUS, alpha } from '../lib/colors';
import { useIsDark } from '../lib/useIsDark';
import { DataIcon } from './Icon';
import type { StatCard as StatCardData } from '../data/types';

export function StatCard({ data }: { data: StatCardData }) {
  const dark = useIsDark();
  const c = STATUS[data.tone].solid;
  const neutral = data.tone === 'total';

  return (
    <div className={cn(card, cardHover, cardPad, 'relative flex min-w-0 flex-col gap-2.5 overflow-hidden')}>
      {/* top accent hairline */}
      <span className="absolute inset-x-0 top-0 h-[3px] opacity-90" style={{ background: c }} />

      <div className="flex items-center justify-between gap-2">
        <span className={cn('min-w-0 flex-auto truncate text-[12.5px] font-semibold leading-tight', textMuted)}>
          {data.label}
        </span>
        <span
          className="grid h-[30px] w-[30px] shrink-0 place-items-center rounded-[9px]"
          style={{ background: alpha(c, dark ? 0.18 : 0.12), color: c }}
        >
          <DataIcon name={data.icon} size={17} strokeWidth={2.1} />
        </span>
      </div>

      <div
        className={cn(mono, 'text-[31px] font-bold leading-none tracking-[-1px]')}
        style={{ color: neutral ? undefined : c }}
      >
        <span className={neutral ? 'text-slate-900 dark:text-slate-100' : undefined}>
          {data.value.toLocaleString()}
        </span>
      </div>

      <div className={cn('text-xs font-medium', textFaint)}>{data.sub}</div>
    </div>
  );
}
