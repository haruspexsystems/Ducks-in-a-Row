import type { CSSProperties } from 'react';
import duckLogo from '@/assets/duck-logo.png';

interface DuckMarkProps {
  size?: number;
  style?: CSSProperties;
  className?: string;
}

/**
 * Ducks in a Row brand mark, the duck knight mascot.
 * Rendered from a transparent PNG asset (src/assets/duck-logo.png).
 * Only the nav, Settings header, and setup wizard use it.
 */
export function DuckMark({ size = 40, style, className }: DuckMarkProps) {
  return (
    <img
      src={duckLogo}
      width={size}
      height={size}
      alt="Ducks in a Row"
      className={className}
      // width/height in style (not just the HTML attrs) so they beat Tailwind
      // Preflight's `img { height: auto }`; contain keeps the mascot inside
      // the square box without distortion or overflow.
      style={{ display: 'block', width: size, height: size, objectFit: 'contain', ...style }}
    />
  );
}
