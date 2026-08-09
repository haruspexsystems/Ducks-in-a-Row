import { card, cardPad, mono, textInk, textFaint, cn } from '../lib/ui';
import { alpha } from '../lib/colors';
import { useIsDark } from '../lib/useIsDark';
import type { ValidationMethod } from '../data/types';

export function ValidationMethods({ data }: { data: ValidationMethod[] }) {
  const dark = useIsDark();
  const total = data.reduce((a, m) => a + m.count, 0);
  const max = Math.max(1, ...data.map((m) => m.count));

  return (
    <div className={cn(card, cardPad, 'flex flex-col gap-3.5')}>
      <div className="flex items-center justify-between gap-2">
        <span className={cn('whitespace-nowrap text-[15px] font-bold leading-tight', textInk)}>Validation Methods</span>
        <span className={cn('shrink-0 whitespace-nowrap text-[11.5px] font-semibold', textFaint)}>
          {total.toLocaleString()} challenges
        </span>
      </div>

      <div className="flex flex-col gap-4">
        {data.map((m, i) => {
          const pct = total === 0 ? 0 : Math.round((m.count / total) * 100);
          // The 500 step is legible on white but drops under WCAG AA on the dark
          // card, so the label and bar take the lightened step there.
          const color = dark ? m.colorDark : m.color;
          return (
            <div key={m.id}>
              <div className="mb-[7px] flex items-baseline justify-between gap-2">
                <span className="flex min-w-0 items-center gap-2">
                  <span className={cn(mono, 'text-[13.5px] font-bold', textInk)}>{m.label}</span>
                  {i === 0 && (
                    <span
                      className="whitespace-nowrap rounded-full px-[7px] py-0.5 text-[10px] font-bold tracking-[0.2px]"
                      style={{ color, background: alpha(color, dark ? 0.2 : 0.12) }}
                    >
                      MOST USED
                    </span>
                  )}
                </span>
                <span className="flex shrink-0 items-baseline gap-[7px]">
                  <span className={cn(mono, 'text-[13.5px] font-bold')} style={{ color }}>{pct}%</span>
                  <span className={cn(mono, 'text-[11.5px]', textFaint)}>{m.count.toLocaleString()}</span>
                </span>
              </div>
              <div className="h-[9px] overflow-hidden rounded-full bg-[#EEF1F5] dark:bg-slate-400/[0.12]">
                <div className="h-full rounded-full" style={{ width: `${(m.count / max) * 100}%`, background: color }} />
              </div>
            </div>
          );
        })}
      </div>

      <div className={cn('mt-auto border-t pt-0.5 text-[11.5px] leading-snug', textFaint, 'border-slate-900/[0.08] dark:border-slate-400/[0.16]')}>
        Bars scaled to the leading method. DNS-01 is required for wildcard certificates.
      </div>
    </div>
  );
}
