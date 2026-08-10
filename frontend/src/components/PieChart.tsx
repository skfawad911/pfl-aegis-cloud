import { motion } from "framer-motion";

export interface Slice { label: string; value: number; color: string; }

export function PieChart({ data, size = 180 }: { data: Slice[]; size?: number }) {
  const total = data.reduce((s, d) => s + d.value, 0);
  const radius = size / 2 - 10;
  const cx = size / 2;
  const cy = size / 2;
  let cumulative = 0;

  const paths = data.map((slice) => {
    const startAngle = (cumulative / total) * Math.PI * 2 - Math.PI / 2;
    cumulative += slice.value;
    const endAngle = (cumulative / total) * Math.PI * 2 - Math.PI / 2;
    const largeArc = slice.value / total > 0.5 ? 1 : 0;
    const x1 = cx + radius * Math.cos(startAngle);
    const y1 = cy + radius * Math.sin(startAngle);
    const x2 = cx + radius * Math.cos(endAngle);
    const y2 = cy + radius * Math.sin(endAngle);
    return {
      d: `M ${cx} ${cy} L ${x1} ${y1} A ${radius} ${radius} 0 ${largeArc} 1 ${x2} ${y2} Z`,
      color: slice.color,
      label: slice.label,
      value: slice.value,
      pct: (slice.value / total) * 100,
    };
  });

  return (
    <div className="flex items-center gap-6">
      <div className="relative" style={{ width: size, height: size }}>
        <svg width={size} height={size} className="-rotate-0">
          {paths.map((p, i) => (
            <motion.path
              key={i}
              d={p.d}
              fill={p.color}
              initial={{ opacity: 0, scale: 0.5 }}
              animate={{ opacity: 0.9, scale: 1 }}
              transition={{ delay: i * 0.08, duration: 0.4 }}
              style={{ transformOrigin: `${cx}px ${cy}px`, filter: `drop-shadow(0 0 6px ${p.color}66)` }}
              stroke="#0B1120"
              strokeWidth={2}
            />
          ))}
          <circle cx={cx} cy={cy} r={radius * 0.55} fill="#1E293B" />
          <text x={cx} y={cy - 4} textAnchor="middle" className="fill-slate-400 text-[10px] font-mono uppercase tracking-widest">Total</text>
          <text x={cx} y={cy + 14} textAnchor="middle" className="fill-white text-lg font-bold font-mono">${total.toFixed(0)}</text>
        </svg>
      </div>
      <div className="flex-1 space-y-1.5 text-xs">
        {paths.map((p, i) => (
          <motion.div
            key={i}
            initial={{ opacity: 0, x: -6 }}
            animate={{ opacity: 1, x: 0 }}
            transition={{ delay: 0.4 + i * 0.06 }}
            className="flex items-center gap-2"
          >
            <span className="w-2.5 h-2.5 rounded-sm" style={{ background: p.color }} />
            <span className="flex-1 text-slate-300 truncate">{p.label}</span>
            <span className="font-mono text-slate-400">${p.value.toFixed(0)}</span>
            <span className="font-mono text-slate-500 w-10 text-right">{p.pct.toFixed(0)}%</span>
          </motion.div>
        ))}
      </div>
    </div>
  );
}
