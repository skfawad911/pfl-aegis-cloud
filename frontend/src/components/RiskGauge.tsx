import { motion } from "framer-motion";
import { ScrambleNumber } from "./ScrambleNumber";

export function RiskGauge({ score, size = 140 }: { score: number; size?: number }) {
  const radius = size / 2 - 12;
  const cx = size / 2;
  const cy = size / 2;
  const circumference = 2 * Math.PI * radius;
  const pct = Math.min(1, score / 10);
  const color = score >= 8 ? "#EF4444" : score >= 5 ? "#F59E0B" : "#10B981";

  return (
    <div className="relative flex items-center justify-center" style={{ width: size, height: size }}>
      <svg width={size} height={size} className="-rotate-90">
        <circle cx={cx} cy={cy} r={radius} fill="none" stroke="#1E293B" strokeWidth={10} />
        <motion.circle
          cx={cx}
          cy={cy}
          r={radius}
          fill="none"
          stroke={color}
          strokeWidth={10}
          strokeLinecap="round"
          strokeDasharray={circumference}
          initial={{ strokeDashoffset: circumference }}
          animate={{ strokeDashoffset: circumference * (1 - pct) }}
          transition={{ duration: 1.5, ease: "easeOut" }}
          style={{ filter: `drop-shadow(0 0 8px ${color})` }}
        />
      </svg>
      <div className="absolute inset-0 flex flex-col items-center justify-center">
        <div className="font-mono font-black text-3xl" style={{ color }}>
          <ScrambleNumber value={score} decimals={1} duration={1500} />
        </div>
        <div className="text-[9px] font-mono uppercase tracking-widest text-slate-500">/ 10.0</div>
      </div>
    </div>
  );
}
