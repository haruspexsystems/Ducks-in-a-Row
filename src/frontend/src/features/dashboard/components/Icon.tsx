import {
  Layers,
  CircleCheck,
  TriangleAlert,
  Ban,
  List,
  CirclePlus,
  RotateCw,
  Clock,
  type LucideIcon,
} from 'lucide-react';
import type { IconName } from '../data/types';

/** Maps the dashboard's data-driven icon names to lucide-react components. */
export const ICONS: Record<IconName, LucideIcon> = {
  layers: Layers,
  check: CircleCheck,
  alert: TriangleAlert,
  ban: Ban,
  list: List,
  plus: CirclePlus,
  rotate: RotateCw,
  clock: Clock,
};

interface DataIconProps {
  name: IconName;
  size?: number;
  color?: string;
  className?: string;
  strokeWidth?: number;
}

/** Renders a lucide icon by its dashboard data name. */
export function DataIcon({ name, size = 18, color, className, strokeWidth = 2 }: DataIconProps) {
  const Cmp = ICONS[name];
  return <Cmp size={size} color={color} className={className} strokeWidth={strokeWidth} />;
}
