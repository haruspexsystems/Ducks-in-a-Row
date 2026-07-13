import { useState } from 'react';
import { card, cardPad, mono, textInk, textMuted, textFaint, cn } from '../lib/ui';
import { STATUS, ACCENT, alpha, getChartColors } from '../lib/colors';
import { useIsDark } from '../lib/useIsDark';
import { useChartWidth } from '../lib/useChartWidth';
import { niceMax, dateLabel } from '../lib/chart';
import type { RegistrationSeries } from '../data/types';

/**
 * Daily new-certificate issuance over the last 30 days (bars).
 *
 * The data contract still carries a `renewals` series, but the CA database
 * does not yet distinguish a renewal from a new issuance, so it is not
 * rendered here (see docs/ducksinarow-dashboard-delta.md).
 */
export function RegistrationsChart({ data }: { data: RegistrationSeries }) {
  const dark = useIsDark();
  const ck = getChartColors(dark);
  const { ref, width: w } = useChartWidth(760);
  const [hover, setHover] = useState<number | null>(null);

  const reg = data.registrations;
  const n = reg.length;
  const yMax = niceMax(Math.max(1, ...reg));

  const H = 214;
  const PADL = 34;
  const PADR = 10;
  const PADT = 14;
  const PADB = 22;
  const plotW = Math.max(10, w - PADL - PADR);
  const plotH = H - PADT - PADB;
  const xC = (i: number) => PADL + (plotW * (i + 0.5)) / n;
  const yV = (v: number) => PADT + plotH * (1 - v / yMax);
  const baseY = PADT + plotH;
  const barW = Math.min(16, (plotW / n) * 0.6);

  const newTotal = reg.reduce((a, b) => a + b, 0);
  const last7 = reg.slice(-7).reduce((a, b) => a + b, 0);
  const prev7 = reg.slice(-14, -7).reduce((a, b) => a + b, 0);
  const delta = prev7 ? Math.round(((last7 - prev7) / prev7) * 100) : 0;
  const up = delta >= 0;

  const yTicks = [0, yMax / 2, yMax];
  const xTickIdx = [0, 6, 12, 18, 24, 29].filter((i) => i < n);

  return (
    <div className={cn(card, cardPad, 'flex flex-col gap-3 overflow-hidden')}>
      {/* header */}
      <div className="flex flex-wrap items-start justify-between gap-3">
        <div className="shrink-0">
          <span className={cn('whitespace-nowrap text-[15px] font-bold leading-tight', textInk)}>Certificates Issued</span>
          <div className={cn('mt-[3px] text-[12.5px]', textMuted)}>Daily new certificates · last 30 days</div>
        </div>
        <div className="flex flex-wrap items-center gap-3.5">
          <div className="text-right">
            <div className={cn(mono, 'text-[20px] font-bold leading-none', textInk)}>{newTotal.toLocaleString()}</div>
            <div className={cn('mt-0.5 text-[11px]', textFaint)}>new · 30d</div>
          </div>
          <div
            className="flex items-center gap-1 whitespace-nowrap rounded-full px-[9px] py-[5px] text-[12.5px] font-bold"
            style={{
              background: alpha(up ? STATUS.success.solid : STATUS.danger.solid, dark ? 0.16 : 0.12),
              color: up ? STATUS.success.solid : STATUS.danger.solid,
            }}
          >
            <span className="text-[11px]">{up ? '▲' : '▼'}</span>
            {Math.abs(delta)}% <span className="font-medium opacity-80">wk</span>
          </div>
        </div>
      </div>

      {/* chart */}
      <div ref={ref} className="relative h-[214px] w-full">
        <svg width={w} height={H} className="block">
          {yTicks.map((tv, i) => (
            <g key={i}>
              <line x1={PADL} y1={yV(tv)} x2={w - PADR} y2={yV(tv)} stroke={ck.grid} strokeWidth="1" />
              <text x={PADL - 7} y={yV(tv) + 3.5} textAnchor="end" fontSize="10" fontFamily="'JetBrains Mono', monospace" fill={ck.faint}>
                {Math.round(tv)}
              </text>
            </g>
          ))}
          {xTickIdx.map((i) => (
            <text key={i} x={xC(i)} y={H - 6} textAnchor="middle" fontSize="10" fontFamily="'JetBrains Mono', monospace" fill={ck.faint}>
              {i === n - 1 ? 'Today' : dateLabel(n - 1 - i)}
            </text>
          ))}

          {/* issuance — bars */}
          {reg.map((v, i) => (
            <rect
              key={i}
              x={xC(i) - barW / 2}
              y={yV(v)}
              width={barW}
              height={Math.max(0, baseY - yV(v))}
              rx={Math.min(3, barW / 2)}
              fill={hover === i ? ACCENT : ck.barFill}
              style={{ transition: 'fill .12s' }}
            />
          ))}

          {/* hover hit areas */}
          {reg.map((_, i) => (
            <rect
              key={`h${i}`}
              x={PADL + (plotW * i) / n}
              y={PADT}
              width={plotW / n}
              height={plotH}
              fill="transparent"
              onMouseEnter={() => setHover(i)}
              onMouseLeave={() => setHover(null)}
            />
          ))}
          {hover != null && (
            <line x1={xC(hover)} y1={PADT} x2={xC(hover)} y2={baseY} stroke={alpha(ACCENT, 0.45)} strokeWidth="1" strokeDasharray="3 3" />
          )}
        </svg>

        {hover != null && (
          <div
            className="pointer-events-none absolute z-[5] -translate-x-1/2 -translate-y-full whitespace-nowrap rounded-[9px] px-2.5 py-[7px] text-white shadow-[0_8px_24px_rgba(0,0,0,.3)]"
            style={{
              left: Math.min(Math.max(xC(hover), 62), w - 62),
              top: yV(reg[hover]) - 8,
              background: ck.tooltipBg,
            }}
          >
            <div className="mb-1 text-[10.5px] text-slate-400">{hover === n - 1 ? 'Today' : dateLabel(n - 1 - hover)}</div>
            <div className="flex items-center gap-1.5">
              <span className="h-2 w-2 rounded-sm" style={{ background: ACCENT }} />
              <span className={cn(mono, 'text-[13px] font-bold')}>{reg[hover]}</span>
              <span className="text-[11px] text-slate-300">new</span>
            </div>
          </div>
        )}
      </div>

      {/* legend */}
      <div className="flex flex-wrap gap-4">
        <div className="flex items-center gap-1.5">
          <span className="h-2.5 w-2.5 rounded-[3px]" style={{ background: ck.barFill }} />
          <span className={cn('whitespace-nowrap text-xs font-semibold', textMuted)}>New certificates / day</span>
        </div>
      </div>
    </div>
  );
}
