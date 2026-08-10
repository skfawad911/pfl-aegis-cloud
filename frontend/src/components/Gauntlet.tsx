import { motion } from "framer-motion";
import { ScrambleNumber } from "./ScrambleNumber";

const LAYERS = [
  { key: "MIN_SPEND", label: "MIN_SPEND", desc: "Baseline spending threshold ≥ $10/day" },
  { key: "ABS_DELTA", label: "ABS_DELTA", desc: "Absolute cost delta vs prior period" },
  { key: "PCT_GROWTH", label: "PCT_GROWTH", desc: "Percentage growth over 24h window" },
  { key: "HIST_BASE", label: "HIST_BASE", desc: "Deviation from historical baseline" },
  { key: "Z_SCORE", label: "Z_SCORE", desc: "Statistical significance relative to 14-day rolling average." },
];

export function Gauntlet({ passed, breached, zScore }: { passed: number; breached: boolean; zScore: number }) {
  return (
    <div className={`rounded-xl border border-slate-800 bg-[#1E293B]/60 backdrop-blur p-5 transition-all ${breached ? "alert-glow" : ""}`}>
      <div className="flex items-center justify-between mb-4">
        <div>
          <div className="text-[10px] font-mono uppercase tracking-widest text-slate-500">Detection Pipeline</div>
          <div className="text-sm font-bold flex items-center gap-2">
            5-Layer Gauntlet
            {breached && <span className="text-[10px] font-mono px-2 py-0.5 rounded bg-[#EF4444]/20 text-[#EF4444] border border-[#EF4444]/40">BREACHED</span>}
          </div>
        </div>
        <div className="text-right">
          <div className="text-[10px] font-mono uppercase tracking-widest text-slate-500">Layers Passed</div>
          <div className="font-mono text-lg font-bold" style={{ color: breached ? "#EF4444" : "#38BDF8" }}>{passed}/5</div>
        </div>
      </div>

      <div className="space-y-2.5">
        {LAYERS.map((layer, i) => {
          const isActive = i < passed;
          const isCurrent = i === passed - 1;
          const isFinal = i === 4 && breached;
          const color = isFinal ? "#EF4444" : isActive ? "#38BDF8" : "#334155";
          return (
            <div key={layer.key} className="tt-wrap group">
              <div className="flex items-center gap-3">
                <div className="w-24 text-[10px] font-mono font-semibold" style={{ color: isActive ? "#F8FAFC" : "#64748B" }}>
                  L{i + 1} · {layer.label}
                </div>
                <div className="flex-1 h-2 bg-slate-800/80 rounded-full overflow-hidden relative">
                  {isActive && (
                    <motion.div
                      initial={{ width: 0 }}
                      animate={{ width: "100%" }}
                      transition={{ duration: 0.6, delay: i * 0.15, ease: "easeOut" }}
                      className="h-full rounded-full"
                      style={{
                        background: `linear-gradient(90deg, ${color}, ${color}dd)`,
                        boxShadow: `0 0 12px ${color}`,
                      }}
                    />
                  )}
                  {isCurrent && !breached && (
                    <motion.div
                      className="absolute inset-y-0 right-0 w-8 bg-gradient-to-r from-transparent to-cyan-300/50"
                      animate={{ opacity: [0.3, 1, 0.3] }}
                      transition={{ repeat: Infinity, duration: 1 }}
                    />
                  )}
                </div>
                <div className="w-6 text-right text-xs font-mono" style={{ color }}>
                  {isActive ? (isFinal ? "✕" : "✓") : "·"}
                </div>
              </div>
              <div className="tt">{layer.desc}</div>
            </div>
          );
        })}
      </div>

      {breached && (
        <motion.div
          initial={{ opacity: 0, y: 8 }}
          animate={{ opacity: 1, y: 0 }}
          transition={{ delay: 0.8 }}
          className="mt-5 pt-4 border-t border-slate-800 flex items-center justify-between"
        >
          <div>
            <div className="text-[10px] font-mono uppercase tracking-widest text-slate-500 tt-wrap">
              Z-Score <span className="text-slate-400">ⓘ</span>
              <span className="tt">Statistical significance relative to 14-day rolling average.</span>
            </div>
            <div className="text-3xl font-mono font-bold text-[#EF4444]">
              <ScrambleNumber value={zScore} decimals={2} duration={1400} />
              <span className="text-sm text-slate-500 ml-1">σ</span>
            </div>
          </div>
          <div className="text-right">
            <div className="text-[10px] font-mono uppercase tracking-widest text-slate-500">Threshold</div>
            <div className="text-xl font-mono text-slate-400">2.50<span className="text-xs">σ</span></div>
          </div>
        </motion.div>
      )}
    </div>
  );
}
