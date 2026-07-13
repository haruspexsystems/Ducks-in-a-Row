import { useLayoutEffect, useRef, useState } from 'react';

/**
 * Tracks the rendered pixel width of an element via ResizeObserver so SVG
 * charts can lay out crisply at any container size.
 *
 *   const { ref, width } = useChartWidth(760);
 *   <div ref={ref}><svg width={width} ... /></div>
 */
export function useChartWidth(initial = 760) {
  const ref = useRef<HTMLDivElement>(null);
  const [width, setWidth] = useState(initial);

  useLayoutEffect(() => {
    const el = ref.current;
    if (!el) return;
    const ro = new ResizeObserver((entries) => {
      for (const e of entries) setWidth(e.contentRect.width);
    });
    ro.observe(el);
    return () => ro.disconnect();
  }, []);

  return { ref, width };
}
