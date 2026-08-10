import { useState } from "react";
import { AnimatePresence, motion } from "framer-motion";
import { AgentPulse, type Agent } from "./components/AgentPulse";
import { TerminalPage } from "./pages/Terminal";
import { WarRoom } from "./pages/WarRoom";

type Statuses = { manager: Agent["status"]; finops: Agent["status"]; security: Agent["status"]; compliance: Agent["status"] };

const INITIAL: Statuses = { manager: "idle", finops: "idle", security: "idle", compliance: "idle" };

export default function App() {
  const [view, setView] = useState<"terminal" | "warroom">("terminal");
  const [query, setQuery] = useState("");
  const [statuses, setStatuses] = useState<Statuses>(INITIAL);

  const agents: Agent[] = [
    { key: "manager",    label: "Manager",    emoji: "🧠", color: "#38BDF8", status: statuses.manager },
    { key: "finops",     label: "FinOps",     emoji: "💰", color: "#10B981", status: statuses.finops },
    { key: "security",   label: "Security",   emoji: "🛡️", color: "#EF4444", status: statuses.security },
    { key: "compliance", label: "Compliance", emoji: "⚖️", color: "#F59E0B", status: statuses.compliance },
  ];

  const handleQuery = (q: string) => {
    setQuery(q);
    setView("warroom");
  };

  const handleBack = () => {
    setView("terminal");
    setStatuses(INITIAL);
  };

  return (
    <div className="min-h-screen grid-bg">
      <AgentPulse agents={agents} />

      <AnimatePresence mode="wait">
        {view === "terminal" ? (
          <motion.div
            key="terminal"
            initial={{ opacity: 0, y: 8 }}
            animate={{ opacity: 1, y: 0 }}
            exit={{ opacity: 0, y: -8 }}
            transition={{ duration: 0.25 }}
          >
            <TerminalPage onQuery={handleQuery} />
          </motion.div>
        ) : (
          <motion.div
            key="warroom"
            initial={{ opacity: 0, y: 8 }}
            animate={{ opacity: 1, y: 0 }}
            exit={{ opacity: 0, y: -8 }}
            transition={{ duration: 0.25 }}
          >
            <WarRoom
              query={query}
              onBack={handleBack}
              onAgentStatusChange={(s) => setStatuses(s)}
            />
          </motion.div>
        )}
      </AnimatePresence>

      {/* Footer */}
      <footer className="border-t border-slate-800/50 mt-12 py-6">
        <div className="max-w-[1600px] mx-auto px-6 flex items-center justify-between text-[10px] font-mono text-slate-500">
          <div>© 2026 Aegis Cloud · Autonomous Cloud Command Terminal</div>
          <div className="flex items-center gap-4">
            <span>build <span className="text-[#38BDF8]">v2.4.1</span></span>
            <span>region <span className="text-[#38BDF8]">us-east-1</span></span>
            <span className="flex items-center gap-1.5">
              <span className="w-1.5 h-1.5 rounded-full bg-[#10B981]" />
              all systems operational
            </span>
          </div>
        </div>
      </footer>
    </div>
  );
}
