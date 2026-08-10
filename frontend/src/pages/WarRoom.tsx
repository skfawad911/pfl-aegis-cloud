import { useEffect, useState, useRef } from "react";
import { motion } from "framer-motion";
import { Timeline, type TimelineEvent } from "../components/Timeline";
import { Gauntlet } from "../components/Gauntlet";
import { PieChart } from "../components/PieChart";
import { VerdictCard, type Verdict } from "../components/VerdictCard";

const AGENTS = ["manager", "finops", "security", "compliance"] as const;
const API_URL = import.meta.env.VITE_API_GATEWAY_URL || "https://lg3988532d.execute-api.ap-south-1.amazonaws.com/prod";

interface Props {
  query: string;
  onBack: () => void;
  onAgentStatusChange: (statuses: Record<typeof AGENTS[number], "idle" | "thinking" | "done" | "alert">) => void;
}

export function WarRoom({ query, onBack, onAgentStatusChange }: Props) {
  const [events, setEvents] = useState<TimelineEvent[]>([]);
  const [thinking, setThinking] = useState<string | null>(null);
  const [gauntletPassed, setGauntletPassed] = useState(0);
  const [breached, setBreached] = useState(false);
  
  const [showEvidence, setShowEvidence] = useState(false);
  const [showVerdict, setShowVerdict] = useState(false);
  const [deployed, setDeployed] = useState(false);
  const [wave, setWave] = useState(false);
  
  const [verdictData, setVerdictData] = useState<Verdict | null>(null);
  const [chartData, setChartData] = useState<{label: string, value: number, color: string}[]>([]);
  const [zScore, setZScore] = useState<number>(0);

  useEffect(() => {
    let isMounted = true;
    let localInterval: NodeJS.Timeout | null = null; 

    const pushEvent = (ev: Omit<TimelineEvent, "id" | "timestamp">) => {
      if (!isMounted) return;
      const ts = new Date().toTimeString().slice(0, 8);
      setEvents((prev) => [...prev, { ...ev, id: Math.random().toString(36).substr(2, 9), timestamp: ts }]);
    };

    const wait = (ms: number) => new Promise((resolve) => setTimeout(resolve, ms));

    const startInvestigation = async () => {
      setEvents([]);
      setChartData([]);
      setGauntletPassed(0);
      setBreached(false);
      setShowEvidence(false);
      setShowVerdict(false);
      onAgentStatusChange({ manager: "idle", finops: "idle", security: "idle", compliance: "idle" });

      pushEvent({ agent: "user", title: query, severity: "info" });
      onAgentStatusChange({ manager: "thinking", finops: "idle", security: "idle", compliance: "idle" });
      setThinking("manager-agent: classifying intent and routing...");

      try {
        const accountMatch = query.match(/\d{12}/);
        const extractedAccount = accountMatch ? accountMatch[0] : "all";
        const dateMatch = query.match(/\d{4}-\d{2}-\d{2}/);
        const extractedDate = dateMatch ? dateMatch[0] : "2026-08-09";

        const chatRes = await fetch(`${API_URL}/chat`, {
          method: "POST",
          headers: { "Content-Type": "application/json" },
          body: JSON.stringify({ message: query, account_id: extractedAccount, date: extractedDate }),
        });

        if (!isMounted) return; 

        const chatData = await chatRes.json();
        
        if (!chatRes.ok || chatData.status === "error") {
          throw new Error(chatData.message || "Failed to start investigation");
        }

        const jobId = chatData.job_id;
        const agentUsed = chatData.agent_used; 

        pushEvent({
          agent: "manager",
          title: `Query classified. Triggering Step Functions.`,
          body: `Routed to: ${agentUsed.toUpperCase()} Agent. AI Confidence: ${chatData.ai_confidence}`,
          severity: "info",
        });

        const newStatuses: any = { manager: "done", finops: "idle", security: "idle", compliance: "idle" };
        if (agentUsed === "all") {
          newStatuses.finops = "thinking"; newStatuses.security = "thinking"; newStatuses.compliance = "thinking";
        } else {
          newStatuses[agentUsed] = "thinking";
        }
        onAgentStatusChange(newStatuses);
        setThinking(`${agentUsed}-agent: gathering AWS evidence and analyzing...`);

        // POLLING LOOP
        localInterval = setInterval(async () => {
          try {
            const pollRes = await fetch(`${API_URL}/anomalies/${jobId}`);
            const pollData = await pollRes.json();

            if (pollData.status === "completed" || (pollData.result && pollData.result !== "null")) {
              if (localInterval) clearInterval(localInterval);
              if (!isMounted) return;

              const rawResult = typeof pollData.result === "string" ? JSON.parse(pollData.result) : pollData.result;
              
              const isCombined = !!rawResult.finops_result || rawResult.agent === "finops_with_correlation" || Array.isArray(rawResult);
              
              let fData = null; let sData = null; let cData = null;

              if (Array.isArray(rawResult)) {
                fData = rawResult.find((r: any) => r?.agent?.includes("finops")) || null;
                sData = rawResult.find((r: any) => r?.agent === "security") || null;
                cData = rawResult.find((r: any) => r?.agent === "compliance") || null;
              } else if (rawResult.finops_result || rawResult.security_result || rawResult.compliance_result) {
                fData = rawResult.finops_result || null;
                sData = rawResult.security_result || null;
                cData = rawResult.compliance_result || null;
              } else {
                if (rawResult.agent?.includes("finops")) fData = rawResult;
                if (rawResult.agent === "security") sData = rawResult;
                if (rawResult.agent === "compliance") cData = rawResult;
              }

              const isIssue = (fData?.is_anomaly) || (sData?.is_incident) || (cData?.is_violation) || false;
              setBreached(isIssue);
              setGauntletPassed(5);
              
              if (fData && fData.analysis_summary && fData.analysis_summary.current_spend !== undefined) {
                const cur = Number(fData.analysis_summary.current_spend) || 0;
                const prev = Number(fData.analysis_summary.previous_spend) || 0;
                setChartData([
                  { label: "Target Cost", value: cur, color: "#EF4444" },
                  { label: "Baseline Cost", value: prev, color: "#38BDF8" }
                ]);
                const delta = fData.cost_delta_pct || fData.usage_delta_pct || 0;
                setZScore(delta ? Math.abs(delta / 10) : 1.1);
              } else {
                const totalFindings = (sData?.total_findings || 0) + (cData?.total_violations || 0) || 100;
                setChartData([{ label: "Scanned Resources", value: totalFindings, color: "#10B981" }]);
                setZScore(isIssue ? 3.42 : 0.5);
              }
              setShowEvidence(true);

              // ── STAGGERED TIMELINE REVEAL ──
              if (isCombined) {
                if (fData) {
                  setThinking("finops-agent: writing financial report...");
                  await wait(800);
                  pushEvent({ agent: "finops", title: "FinOps Scan Complete", body: fData.financial_root_cause || "No cost anomalies detected.", severity: fData.is_anomaly ? "alert" : "info" });
                }
                if (sData) {
                  setThinking("security-agent: analyzing threat vectors...");
                  await wait(800);
                  pushEvent({ agent: "security", title: "Security Scan Complete", body: sData.reasoning || "No security threats detected.", severity: sData.is_incident ? "alert" : "info" });
                }
                if (cData) {
                  setThinking("compliance-agent: cross-referencing policies...");
                  await wait(800);
                  pushEvent({ agent: "compliance", title: "Compliance Scan Complete", body: cData.reasoning || "No policy violations detected.", severity: cData.is_violation ? "alert" : "info" });
                }
                setThinking("manager-agent: synthesizing final consensus...");
                await wait(1000);
              }

              // Build Reasons List
              const combinedReasons: any[] = [];
              if (fData?.evidence_points) fData.evidence_points.forEach((ev: string) => combinedReasons.push({icon: "💰", agent: "FINOPS", text: ev, color: "#10B981"}));
              else if (fData?.financial_root_cause) combinedReasons.push({icon: "💰", agent: "FINOPS", text: fData.financial_root_cause, color: fData.is_anomaly ? "#EF4444" : "#10B981"});
              
              if (sData?.evidence && sData.evidence.length > 0) sData.evidence.forEach((ev: string) => combinedReasons.push({icon: "🛡️", agent: "SECURITY", text: ev, color: "#EF4444"}));
              else if (sData?.reasoning) combinedReasons.push({icon: "🛡️", agent: "SECURITY", text: sData.reasoning, color: sData.is_incident ? "#EF4444" : "#10B981"});

              if (cData?.evidence && cData.evidence.length > 0) cData.evidence.forEach((ev: string) => combinedReasons.push({icon: "⚖️", agent: "COMPLIANCE", text: ev, color: "#F59E0B"}));
              else if (cData?.reasoning) combinedReasons.push({icon: "⚖️", agent: "COMPLIANCE", text: cData.reasoning, color: cData.is_violation ? "#F59E0B" : "#10B981"});

              let allRecs: string[] = [];
              if (sData?.recommendations) allRecs = [...allRecs, ...sData.recommendations];
              if (cData?.recommendations) allRecs = [...allRecs, ...cData.recommendations];
              if (fData?.recommendations) allRecs = [...allRecs, ...fData.recommendations];

              const mainSummary = isCombined 
                ? "Consensus reached. Multi-agent correlation complete." 
                : (rawResult.reasoning || rawResult.financial_root_cause || "Investigation concluded.");

              pushEvent({
                agent: "manager",
                title: "Investigation Complete.",
                body: mainSummary,
                severity: isIssue ? "alert" : "info",
              });

              // Final Verdict Card
              const finalVerdict: Verdict = {
                caseId: jobId.substring(0, 8),
                severity: sData?.severity || cData?.severity || fData?.severity || rawResult.severity || (isIssue ? "HIGH" : "NONE"),
                summary: isCombined ? (sData?.reasoning || fData?.financial_root_cause || cData?.reasoning || mainSummary) : mainSummary,
                location: `Account: ${extractedAccount === "all" ? "Global Focus" : extractedAccount}`,
                riskScore: isIssue ? 8.5 : 0.0,
                reasons: combinedReasons,
                remediation: allRecs.length > 0 ? allRecs[0] : "No immediate action required.",
              };

              setVerdictData(finalVerdict);
              setThinking(null);
              setShowVerdict(true);
              
              const finalStatus = isIssue ? "alert" : "done";
              onAgentStatusChange({ manager: "done", finops: finalStatus, security: finalStatus, compliance: finalStatus });
            } 
            else if (pollData.status === "error" || pollData.status === "FAILED") {
              throw new Error(pollData.error_message || "Step Function Agent failed to respond.");
            }
          } catch (err: any) {
             console.error("Polling error:", err);
             if (localInterval) clearInterval(localInterval);
             if (!isMounted) return;
             pushEvent({ agent: "manager", title: "UI Parsing Error", body: err.message, severity: "alert" });
             setThinking(null);
             onAgentStatusChange({ manager: "done", finops: "idle", security: "idle", compliance: "idle" });
          }
        }, 2000);

      } catch (error: any) {
        if (!isMounted) return;
        pushEvent({ agent: "manager", title: "Investigation Failed", body: error.message, severity: "alert" });
        setThinking(null);
      }
    };

    startInvestigation();

    return () => {
      isMounted = false;
      if (localInterval) clearInterval(localInterval);
    };
  }, [query]);

  const handleDeploy = () => {
    setDeployed(true);
    setWave(true);
    setTimeout(() => setWave(false), 1200);
  };

  return (
    <>
      {wave && <div className="shield-wave" />}
      <div className="max-w-[1600px] mx-auto px-6 py-6">
        <div className="flex items-center justify-between mb-5">
          <button onClick={onBack} className="text-xs font-mono text-slate-400 hover:text-[#38BDF8] transition-colors flex items-center gap-1">
            ← back to terminal
          </button>
          <div className="text-[10px] font-mono uppercase tracking-widest text-slate-500">
            War Room · investigation active
          </div>
        </div>

        <div className="rounded-lg border border-slate-800 bg-[#1E293B]/50 backdrop-blur p-4 mb-6 flex items-center gap-3">
          <span className="text-[#38BDF8] font-mono">▸</span>
          <span className="font-mono text-sm text-slate-200 flex-1 truncate">{query}</span>
        </div>

        <div className="grid grid-cols-12 gap-5">
          <div className="col-span-12 lg:col-span-5">
            <div className="rounded-xl border border-slate-800 bg-[#1E293B]/40 backdrop-blur p-5 sticky top-24 max-h-[calc(100vh-140px)] overflow-y-auto">
              <div className="flex items-center justify-between mb-4">
                <div>
                  <div className="text-[10px] font-mono uppercase tracking-widest text-slate-500">Investigation Timeline</div>
                  <div className="text-sm font-bold">Agent Thinking Chain</div>
                </div>
                {thinking && (
                  <div className="flex items-center gap-1.5 text-[10px] font-mono text-[#10B981]">
                    <motion.span className="w-1.5 h-1.5 rounded-full bg-[#10B981]" animate={{ opacity: [1, 0.3, 1] }} transition={{ repeat: Infinity, duration: 1.4 }} />
                    live
                  </div>
                )}
              </div>
              <Timeline events={events} thinking={thinking} />
            </div>
          </div>

          <div className="col-span-12 lg:col-span-7 space-y-5">
            <div className="rounded-xl border border-slate-800 bg-[#1E293B]/40 backdrop-blur p-5">
              <div className="flex items-center justify-between mb-4">
                <div>
                  <div className="text-[10px] font-mono uppercase tracking-widest text-slate-500">Evidence Board</div>
                  <div className="text-sm font-bold">AWS Data Context</div>
                </div>
              </div>
              {showEvidence && chartData.length > 0 ? (
                <PieChart data={chartData} />
              ) : (
                <div className="animate-pulse h-32 bg-slate-800/50 rounded-md"></div>
              )}
            </div>

            {showEvidence ? (
              <Gauntlet passed={gauntletPassed} breached={breached} zScore={zScore} />
            ) : null}

            {showVerdict && verdictData ? (
              <VerdictCard verdict={verdictData} onDeploy={handleDeploy} deployed={deployed} />
            ) : showEvidence ? (
              <div className="rounded-xl border border-slate-800 bg-[#1E293B]/40 p-5">
                <div className="text-[10px] font-mono uppercase tracking-widest text-slate-500 mb-3">Verdict · pending consensus</div>
                <div className="animate-pulse space-y-3">
                  <div className="h-4 bg-slate-700 rounded w-3/4"></div>
                  <div className="h-4 bg-slate-700 rounded w-1/2"></div>
                </div>
              </div>
            ) : null}
          </div>
        </div>
      </div>
    </>
  );
}
