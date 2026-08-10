import { motion } from "framer-motion";
import { RiskGauge } from "./RiskGauge";
import { ScrambleNumber } from "./ScrambleNumber";

export interface Verdict {
  caseId: string;
  severity: "CRITICAL" | "HIGH" | "MEDIUM";
  summary: string;
  location: string;
  riskScore: number;
  reasons: { icon: string; agent: string; text: string; color: string }[];
  remediation: string;
}

export function VerdictCard({ verdict, onDeploy, deployed }: { verdict: Verdict; onDeploy: () => void; deployed: boolean }) {
  return (
    <motion.div
      initial={{ opacity: 0, y: 12 }}
      animate={{ opacity: 1, y: 0 }}
      transition={{ delay: 0.4, duration: 0.5 }}
      className="rounded-xl border border-[#EF4444]/40 bg-gradient-to-br from-[#1E293B] to-[#0f1627] overflow-hidden alert-glow"
    >
      {/* Header */}
      <div className="bg-[#EF4444]/10 border-b border-[#EF4444]/30 px-5 py-3 flex items-center justify-between">
        <div className="flex items-center gap-3">
          <div className="w-2 h-2 rounded-full bg-[#EF4444] pulse-dot" style={{ color: "#EF4444" }} />
          <div>
            <div className="text-[10px] font-mono uppercase tracking-widest text-[#EF4444]">
              CASE #{verdict.caseId} · {verdict.severity} ANOMALY
            </div>
            <div className="text-sm font-bold">{verdict.summary}</div>
          </div>
        </div>
        <div className="text-right">
          <div className="text-[9px] font-mono uppercase tracking-widest text-slate-500">Location</div>
          <div className="text-xs font-mono text-[#F59E0B]">{verdict.location}</div>
        </div>
      </div>

      <div className="p-5">
        <div className="flex items-start gap-6">
          <div className="flex flex-col items-center gap-2">
            <RiskGauge score={verdict.riskScore} size={130} />
            <div className="text-[9px] font-mono uppercase tracking-widest text-slate-500">Risk Score</div>
          </div>

          <div className="flex-1">
            <div className="text-[10px] font-mono uppercase tracking-widest text-slate-500 mb-2">The "Why" — Agent Consensus</div>
            <div className="space-y-2">
              {verdict.reasons.map((r, i) => (
                <motion.div
                  key={i}
                  initial={{ opacity: 0, x: -8 }}
                  animate={{ opacity: 1, x: 0 }}
                  transition={{ delay: 0.6 + i * 0.15 }}
                  className="flex items-start gap-3 p-2.5 rounded-md bg-[#0B1120]/60 border border-slate-800"
                >
                  <div className="text-lg leading-none mt-0.5">{r.icon}</div>
                  <div className="flex-1">
                    <div className="text-[10px] font-mono uppercase tracking-wider" style={{ color: r.color }}>{r.agent}</div>
                    <div className="text-xs text-slate-200 leading-relaxed">{r.text}</div>
                  </div>
                </motion.div>
              ))}
            </div>
          </div>
        </div>

        {/* Impact bar */}
        <div className="mt-5 grid grid-cols-3 gap-3">
          <Stat label="Daily Bleed" value={<><span className="text-[#EF4444]">$</span><ScrambleNumber value={150} decimals={0} /></>} sub="+340%" subColor="#EF4444" />
          <Stat label="Time to Detect" value={<ScrambleNumber value={4.2} decimals={1} suffix="s" />} sub="Autonomous" subColor="#38BDF8" />
          <Stat label="Confidence" value={<ScrambleNumber value={98} decimals={0} suffix="%" />} sub="4/4 agents" subColor="#10B981" />
        </div>

        {/* Remediation */}
        <div className="mt-5 rounded-md border border-slate-800 bg-[#0B1120]/60 p-4">
          <div className="flex items-center justify-between mb-2">
            <div className="text-[10px] font-mono uppercase tracking-widest text-slate-500">Recommended Action</div>
            <div className="text-[10px] font-mono text-[#38BDF8]">TERRAFORM · dry-run OK</div>
          </div>
          <div className="text-xs text-slate-300 mb-3 font-mono">{verdict.remediation}</div>

          <motion.button
            onClick={onDeploy}
            disabled={deployed}
            whileHover={!deployed ? { scale: 1.01 } : {}}
            whileTap={!deployed ? { scale: 0.99 } : {}}
            className={`w-full py-3.5 rounded-lg font-bold text-sm tracking-wider uppercase transition-all relative overflow-hidden ${
              deployed
                ? "bg-[#10B981] text-[#0B1120]"
                : "bg-gradient-to-r from-[#EF4444] to-[#F59E0B] text-white hover:shadow-[0_0_30px_-5px_rgba(239,68,68,0.7)]"
            }`}
          >
            {deployed ? "✓ SHIELD DEPLOYED · INSTANCE TERMINATED" : "🛡️  DEPLOY SHIELD  ·  EXECUTE FIX"}
            {!deployed && (
              <motion.span
                className="absolute inset-0 bg-white/20"
                initial={{ x: "-100%" }}
                animate={{ x: "100%" }}
                transition={{ repeat: Infinity, duration: 2.5, ease: "linear" }}
                style={{ mixBlendMode: "overlay" }}
              />
            )}
          </motion.button>
        </div>
      </div>
    </motion.div>
  );
}

function Stat({ label, value, sub, subColor }: { label: string; value: React.ReactNode; sub: string; subColor: string }) {
  return (
    <div className="rounded-md border border-slate-800 bg-[#0B1120]/60 p-3">
      <div className="text-[9px] font-mono uppercase tracking-widest text-slate-500">{label}</div>
      <div className="text-lg font-mono font-bold text-white">{value}</div>
      <div className="text-[10px] font-mono" style={{ color: subColor }}>{sub}</div>
    </div>
  );
}
