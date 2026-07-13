import { card, cardPad, mono, textInk, textInkSoft, textMuted, textFaint, cn } from '../lib/ui';
import { STATUS } from '../lib/colors';
import type { FleetHealth as FleetHealthData, HealthSegment } from '../data/types';

function segColor(tone: HealthSegment['tone']): string {
  if (tone === 'pending') return '#94A3B8';
  return STATUS[tone].solid;
}

export function FleetHealth({ data }: { data: FleetHealthData }) {
  const size = 176;
  const stroke = 17;
  const r = (size - stroke) / 2;
  const C = 2 * Math.PI * r;
  const total = data.segments.reduce((a, s) => a + s.count, 0);
  const denom = total || 1; // avoid dividing by zero when the fleet is empty
  const gap = 0.012; // fractional gap between arcs

  // A null score means nothing is scoreable yet (fresh install): render a
  // neutral empty state instead of a misleading "100% Healthy".
  const hasScore = data.score !== null;
  const score = data.score ?? 0;
  const verdict = !hasScore ? 'No certificates yet' : score >= 80 ? 'Healthy' : score >= 60 ? 'Watch' : 'At risk';
  const verdictColor = !hasScore
    ? '#94A3B8'
    : score >= 80
      ? STATUS.success.solid
      : score >= 60
        ? STATUS.warning.solid
        : STATUS.danger.solid;

  let acc = 0;
  const arcs = data.segments.map((s) => {
    const frac = s.count / denom;
    const len = Math.max(0, (frac - gap) * C);
    const arc = { len, gap: C - len, offset: -acc * C, color: segColor(s.tone) };
    acc += frac;
    return arc;
  });

  return (
    <div className={cn(card, cardPad, 'flex flex-col gap-3.5')}>
      <div className="flex items-center justify-between gap-2">
        <span className={cn('whitespace-nowrap text-[15px] font-bold leading-tight', textInk)}>Fleet Health</span>
        <span className={cn('shrink-0 whitespace-nowrap text-[11.5px] font-semibold', textFaint)}>
          {total.toLocaleString()} certs
        </span>
      </div>

      <div className="relative flex items-center justify-center px-0 pb-0.5 pt-1">
        <svg width={size} height={size} viewBox={`0 0 ${size} ${size}`} className="-rotate-90">
          <circle cx={size / 2} cy={size / 2} r={r} fill="none" strokeWidth={stroke} className="stroke-[#EEF1F5] dark:stroke-slate-400/[0.12]" />
          {arcs.map((a, i) => (
            <circle
              key={i}
              cx={size / 2}
              cy={size / 2}
              r={r}
              fill="none"
              stroke={a.color}
              strokeWidth={stroke}
              strokeDasharray={`${a.len} ${a.gap}`}
              strokeDashoffset={a.offset}
              strokeLinecap="round"
            />
          ))}
        </svg>

        {/* center */}
        <div className="absolute inset-0 flex flex-col items-center justify-center gap-px">
          <div className={cn(mono, 'text-[36px] font-bold leading-none tracking-[-1px]', textInk)}>
            {hasScore ? (
              <>
                {score}
                <span className={cn('text-[17px]', textFaint)}>%</span>
              </>
            ) : (
              <span className={textFaint}>—</span>
            )}
          </div>
          <div className="mt-0.5 flex items-center gap-[5px]">
            {hasScore && <span className="h-[7px] w-[7px] rounded-full" style={{ background: verdictColor }} />}
            <span className="text-[12.5px] font-bold tracking-[0.2px]" style={{ color: verdictColor }}>
              {verdict}
            </span>
          </div>
        </div>
      </div>

      {/* legend */}
      <div className="grid grid-cols-2 gap-x-3.5 gap-y-[7px]">
        {data.segments.map((s) => (
          <div key={s.key} className="flex min-w-0 items-center gap-2">
            <span className="h-[9px] w-[9px] shrink-0 rounded-[3px]" style={{ background: segColor(s.tone) }} />
            <span className={cn('flex-1 truncate text-[12.5px] font-medium', textMuted)}>{s.label}</span>
            <span className={cn(mono, 'text-[12.5px] font-semibold', textInkSoft)}>{s.count.toLocaleString()}</span>
          </div>
        ))}
      </div>
    </div>
  );
}
