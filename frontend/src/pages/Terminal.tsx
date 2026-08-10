import { useState } from "react";
import { motion } from "framer-motion";
import { Heatmap, type Account } from "../components/Heatmap";
import { ScrambleNumber } from "../components/ScrambleNumber";

const SUGGESTIONS = [
  { label: "Investigate_Last_Anomaly", color: "#EF4444", icon: "🔍" },
  { label: "Audit_S3_Exposure", color: "#F59E0B", icon: "🗄️" },
  { label: "Daily_Cost_Summary", color: "#10B981", icon: "📊" },
  { label: "Show_IAM_Drift", color: "#38BDF8", icon: "🔑" },
  { label: "Simulate_Region_Failover", color: "#38BDF8", icon: "🌐" },
];

export function TerminalPage({ onQuery }: { onQuery: (q: string) => void }) {
  const [query, setQuery] = useState("");

  const submit = (q: string) => {
    const final = q.trim();
    if (!final) return;
    onQuery(final);
  };

  return (
    <div className="max-w-[1400px] mx-auto px-6 py-10">
      {/* Hero */}
      <div className="text-center mb-8">
        <motion.div
          initial={{ opacity: 0, y: -8 }}
          animate={{ opacity: 1, y: 0 }}
          className="inline-flex items-center gap-2 px-3 py-1 rounded-full border border-[#38BDF8]/30 bg-[#38BDF8]/10 text-[10px] font-mono uppercase tracking-widest text-[#38BDF8] mb-4"
        >
          <span className="w-1.5 h-1.5 rounded-full bg-[#38BDF8] pulse-dot" style={{ color: "#38BDF8" }} />
          4 Agents Online · 18 Accounts Monitored · Step Functions Active
        </motion.div>

        <h1 className="text-4xl md:text-6xl font-black tracking-tight mb-3">
          The problem <span className="bg-gradient-to-r from-[#EF4444] via-[#F59E0B] to-[#38BDF8] bg-clip-text text-transparent">finds you.</span>
        </h1>
        <p className="text-slate-400 max-w-2xl mx-auto text-sm md:text-base">
          Aegis Cloud replaces the dashboard with an autonomous command terminal. Ask a question — the agents investigate, correlate, and deliver a verdict with a one-click fix.
        </p>
      </div>

      {/* Hero input */}
      <motion.div
        initial={{ opacity: 0, y: 12 }}
        animate={{ opacity: 1, y: 0 }}
        transition={{ delay: 0.15 }}
        className="max-w-3xl mx-auto"
      >
        <div className="rounded-2xl border border-[#38BDF8]/30 bg-[#1E293B]/70 backdrop-blur hero-glow overflow-hidden">
          <div className="flex items-center gap-2 px-4 py-2 border-b border-slate-800/80 bg-[#0B1120]/50">
            <span className="w-2.5 h-2.5 rounded-full bg-[#EF4444]/70" />
            <span className="w-2.5 h-2.5 rounded-full bg-[#F59E0B]/70" />
            <span className="w-2.5 h-2.5 rounded-full bg-[#10B981]/70" />
            <span className="ml-2 text-[10px] font-mono text-slate-500 tracking-widest">aegis@command-terminal ~ %</span>
          </div>
          <form
            onSubmit={(e) => { e.preventDefault(); submit(query); }}
            className="p-5"
          >
            <div className="flex items-start gap-3">
              <span className="text-[#38BDF8] font-mono text-xl mt-1">▸</span>
              <textarea
                value={query}
                onChange={(e) => setQuery(e.target.value)}
                onKeyDown={(e) => { if (e.key === "Enter" && !e.shiftKey) { e.preventDefault(); submit(query); } }}
                placeholder="Why did AWS costs spike overnight?  What's exposed to the internet right now?"
                className="flex-1 bg-transparent outline-none resize-none text-white placeholder:text-slate-600 font-mono text-base leading-relaxed min-h-[64px]"
                rows={2}
                autoFocus
              />
            </div>
            <div className="flex items-center justify-between mt-3 pt-3 border-t border-slate-800/60">
              <div className="flex items-center gap-3 text-[10px] font-mono text-slate-500">
                <span>⌘ Enter to dispatch</span>
                <span className="hidden sm:inline">·</span>
                <span className="hidden sm:inline">Model: <span className="text-[#38BDF8]">aegis-manager-v2</span></span>
              </div>
              <button
                type="submit"
                className="px-4 py-2 rounded-md bg-[#38BDF8] text-[#0B1120] text-xs font-bold uppercase tracking-wider hover:bg-[#7DD3FC] transition-colors"
              >
                Dispatch Agents →
              </button>
            </div>
          </form>
        </div>

        {/* Suggestions */}
        <div className="mt-6">
          <div className="text-[10px] font-mono uppercase tracking-widest text-slate-500 mb-2 text-center">Frequent Investigations</div>
          <div className="flex flex-wrap gap-2 justify-center">
            {SUGGESTIONS.map((s) => (
              <button
                key={s.label}
                onClick={() => submit(s.label.replace(/_/g, " "))}
                className="group px-3 py-1.5 rounded-md border text-xs font-mono transition-all hover:scale-[1.03]"
                style={{
                  borderColor: `${s.color}44`,
                  background: `${s.color}0F`,
                  color: s.color,
                }}
              >
                <span className="mr-1.5">{s.icon}</span>[{s.label}]
              </button>
            ))}
          </div>
        </div>
      </motion.div>

      {/* Stats strip */}
      <div className="mt-14 grid grid-cols-2 md:grid-cols-4 gap-3 max-w-4xl mx-auto">
        <MetricCard label="Monthly Cloud Spend" value={<><span className="text-slate-500">$</span><ScrambleNumber value={487214} decimals={0} /></>} delta="-12% ↓ saved" color="#10B981" />
        <MetricCard label="Active Anomalies" value={<ScrambleNumber value={1} decimals={0} />} delta="1 critical" color="#EF4444" />
        <MetricCard label="Compliance Score" value={<ScrambleNumber value={94.6} decimals={1} suffix="%" />} delta="SOC2 · ISO27001" color="#F59E0B" />
        <MetricCard label="Auto-Remediated" value={<ScrambleNumber value={247} decimals={0} />} delta="last 30 days" color="#38BDF8" />
      </div>

      {/* Heatmap */}
      <div className="mt-10">
        <Heatmap onAnomalyClick={(a: Account) => submit(`Investigate anomaly on ${a.id}`)} />
      </div>

      {/* Bottom terminal-esque log */}
      <div className="mt-8 rounded-lg border border-slate-800 bg-[#0B1120]/80 p-4 font-mono text-[11px] leading-relaxed max-w-[1400px] mx-auto">
        <div className="text-slate-500 mb-1">// live-tail · agent-orchestrator.log</div>
        <div className="text-slate-400"><span className="text-[#10B981]">[12:04:19]</span> manager-agent: dispatch complete — 4/4 workers healthy</div>
        <div className="text-slate-400"><span className="text-[#10B981]">[12:04:22]</span> finops-agent: baseline recalibrated · 14d rolling window</div>
        <div className="text-slate-400"><span className="text-[#F59E0B]">[12:04:28]</span> compliance-agent: <span className="text-[#F59E0B]">warning</span> — region drift detected in <span className="text-[#38BDF8]">ml-af-south-1</span></div>
        <div className="text-slate-400"><span className="text-[#EF4444]">[12:04:31]</span> security-agent: <span className="text-[#EF4444]">alert</span> — anomalous IAM assumption on i-0f3e2a71c9<span className="blink">▊</span></div>
      </div>
    </div>
  );
}

function MetricCard({ label, value, delta, color }: { label: string; value: React.ReactNode; delta: string; color: string }) {
  return (
    <div className="rounded-lg border border-slate-800 bg-[#1E293B]/60 backdrop-blur p-4">
      <div className="text-[10px] font-mono uppercase tracking-widest text-slate-500">{label}</div>
      <div className="text-2xl font-mono font-bold text-white mt-1">{value}</div>
      <div className="text-[10px] font-mono mt-1" style={{ color }}>{delta}</div>
    </div>
  );
}
