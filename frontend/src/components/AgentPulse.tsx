import { motion } from "framer-motion";

export type AgentStatus = "idle" | "thinking" | "done" | "alert";

export interface Agent {
  key: "manager" | "finops" | "security" | "compliance";
  label: string;
  emoji: string;
  color: string;
  status: AgentStatus;
}

const dotColor = (s: AgentStatus) => {
  switch (s) {
    case "thinking": return "#38BDF8";
    case "done": return "#10B981";
    case "alert": return "#EF4444";
    default: return "#64748B";
  }
};

export function AgentPulse({ agents }: { agents: Agent[] }) {
  return (
    <div className="w-full border-b border-slate-800/80 bg-[#0B1120]/80 backdrop-blur-md sticky top-0 z-30">
      <div className="max-w-[1600px] mx-auto px-6 py-3 flex items-center justify-between">
        <div className="flex items-center gap-3">
          <div className="w-8 h-8 rounded-md bg-gradient-to-br from-[#38BDF8] to-[#0EA5E9] flex items-center justify-center text-[#0B1120] font-black text-lg shadow-lg shadow-cyan-500/30">Æ</div>
          <div>
            <div className="text-sm font-bold tracking-wide">AEGIS CLOUD</div>
            <div className="text-[10px] text-slate-500 font-mono uppercase tracking-widest">Autonomous Command Terminal</div>
          </div>
        </div>

        <div className="flex items-center gap-6">
          {agents.map((a) => (
            <div key={a.key} className="flex items-center gap-2.5">
              <div className="relative" style={{ zIndex: 1 }}>
                <div
                  className={`relative w-10 h-10 rounded-full flex items-center justify-center text-base bg-[#1E293B] border border-slate-700 ${a.status === "thinking" ? "agent-ring-thinking" : ""}`}
                  style={{ boxShadow: a.status === "alert" ? "0 0 20px rgba(239,68,68,0.6)" : a.status === "done" ? "0 0 15px rgba(16,185,129,0.4)" : undefined }}
                >
                  {a.emoji}
                  <span
                    className={`absolute -bottom-0.5 -right-0.5 w-3 h-3 rounded-full border-2 border-[#0B1120] ${a.status === "thinking" || a.status === "alert" ? "pulse-dot" : ""}`}
                    style={{ background: dotColor(a.status), color: dotColor(a.status) }}
                  />
                </div>
              </div>
              <div>
                <div className="text-[11px] font-semibold uppercase tracking-wider">{a.label}</div>
                <div className="text-[10px] font-mono" style={{ color: dotColor(a.status) }}>
                  {a.status === "idle" && "STANDBY"}
                  {a.status === "thinking" && "ANALYZING…"}
                  {a.status === "done" && "READY"}
                  {a.status === "alert" && "ALERT"}
                </div>
              </div>
            </div>
          ))}
        </div>

        <div className="hidden lg:flex items-center gap-2 text-xs font-mono text-slate-400">
          <motion.span animate={{ opacity: [1, 0.4, 1] }} transition={{ repeat: Infinity, duration: 2 }} className="w-2 h-2 rounded-full bg-[#10B981]" />
          <span>us-east-1 · af-south-1 · eu-west-2</span>
        </div>
      </div>
    </div>
  );
}
