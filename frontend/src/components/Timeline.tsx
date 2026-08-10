import { motion, AnimatePresence } from "framer-motion";
import type { ReactNode } from "react";

export interface TimelineEvent {
  id: string;
  agent: "user" | "manager" | "finops" | "security" | "compliance" | "system";
  title: string;
  body?: ReactNode;
  code?: { lang: string; content: ReactNode };
  timestamp: string;
  severity?: "info" | "success" | "warning" | "alert";
}

const AGENT_META: Record<TimelineEvent["agent"], { color: string; emoji: string; name: string }> = {
  user: { color: "#F8FAFC", emoji: "👤", name: "You" },
  manager: { color: "#38BDF8", emoji: "🧠", name: "Manager Agent" },
  finops: { color: "#10B981", emoji: "💰", name: "FinOps Agent" },
  security: { color: "#EF4444", emoji: "🛡️", name: "Security Agent" },
  compliance: { color: "#F59E0B", emoji: "⚖️", name: "Compliance Agent" },
  system: { color: "#64748B", emoji: "⚙️", name: "System" },
};

export function Timeline({ events, thinking }: { events: TimelineEvent[]; thinking?: string | null }) {
  return (
    <div className="relative pl-8">
      {/* vertical line */}
      <div className="absolute left-[15px] top-2 bottom-2 w-px bg-gradient-to-b from-slate-800 via-slate-700 to-slate-800" />

      <AnimatePresence initial={false}>
        {events.map((e, idx) => {
          const meta = AGENT_META[e.agent];
          return (
            <motion.div
              key={e.id}
              initial={{ opacity: 0, x: -8 }}
              animate={{ opacity: 1, x: 0 }}
              transition={{ duration: 0.35, delay: idx === events.length - 1 ? 0.05 : 0 }}
              className="relative mb-5"
            >
              <div
                className="absolute -left-8 top-1 w-8 h-8 rounded-full flex items-center justify-center text-sm border-2 border-[#0B1120]"
                style={{ background: "#1E293B", boxShadow: `0 0 0 1px ${meta.color}55` }}
              >
                {meta.emoji}
              </div>

              <div className="flex items-baseline gap-2 mb-1">
                <span className="text-xs font-semibold" style={{ color: meta.color }}>{meta.name}</span>
                <span className="text-[10px] font-mono text-slate-500">{e.timestamp}</span>
                {e.severity && (
                  <span
                    className="text-[9px] font-mono uppercase tracking-widest px-1.5 py-px rounded"
                    style={{
                      color: e.severity === "alert" ? "#EF4444" : e.severity === "warning" ? "#F59E0B" : e.severity === "success" ? "#10B981" : "#64748B",
                      background: e.severity === "alert" ? "rgba(239,68,68,0.1)" : e.severity === "warning" ? "rgba(245,158,11,0.1)" : e.severity === "success" ? "rgba(16,185,129,0.1)" : "rgba(100,116,139,0.1)",
                    }}
                  >
                    {e.severity}
                  </span>
                )}
              </div>

              <div className="text-sm text-slate-200 leading-relaxed">{e.title}</div>
              {e.body && <div className="text-xs text-slate-400 mt-1 leading-relaxed">{e.body}</div>}

              {e.code && (
                <div className="mt-2 rounded-md border border-slate-800 bg-[#0B1120] overflow-hidden text-[11px] font-mono">
                  <div className="flex items-center justify-between px-3 py-1.5 border-b border-slate-800 bg-[#0f1627]">
                    <div className="flex items-center gap-1.5">
                      <span className="w-2 h-2 rounded-full bg-[#EF4444]/70" />
                      <span className="w-2 h-2 rounded-full bg-[#F59E0B]/70" />
                      <span className="w-2 h-2 rounded-full bg-[#10B981]/70" />
                    </div>
                    <span className="text-[10px] text-slate-500 uppercase tracking-wider">{e.code.lang}</span>
                  </div>
                  <pre className="px-4 py-3 overflow-x-auto leading-relaxed text-slate-300">{e.code.content}</pre>
                </div>
              )}
            </motion.div>
          );
        })}
      </AnimatePresence>

      {thinking && (
        <motion.div
          initial={{ opacity: 0 }}
          animate={{ opacity: 1 }}
          className="relative mb-5"
        >
          <div className="absolute -left-8 top-1 w-8 h-8 rounded-full flex items-center justify-center text-sm border-2 border-[#0B1120] agent-ring-thinking" style={{ background: "#1E293B" }}>
            <motion.span animate={{ opacity: [0.5, 1, 0.5] }} transition={{ repeat: Infinity, duration: 1.2 }}>⚡</motion.span>
          </div>
          <div className="text-xs font-mono text-[#38BDF8]">{thinking}<span className="blink">▊</span></div>
        </motion.div>
      )}
    </div>
  );
}
