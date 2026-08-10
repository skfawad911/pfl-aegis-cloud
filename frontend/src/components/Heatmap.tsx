import { motion } from "framer-motion";

export interface Account {
  id: string;
  region: string;
  status: "stable" | "warning" | "anomaly";
  spend: number;
}

const REGIONS: Account[] = [
  { id: "prod-us-east-1", region: "us-east-1", status: "stable", spend: 2340 },
  { id: "prod-us-west-2", region: "us-west-2", status: "stable", spend: 1890 },
  { id: "prod-eu-west-2", region: "eu-west-2", status: "stable", spend: 1420 },
  { id: "prod-eu-north-1", region: "eu-north-1", status: "warning", spend: 890 },
  { id: "prod-ap-south-1", region: "ap-south-1", status: "stable", spend: 670 },
  { id: "prod-ap-northeast-1", region: "ap-northeast-1", status: "stable", spend: 780 },
  { id: "dev-us-east-1", region: "us-east-1", status: "stable", spend: 340 },
  { id: "dev-eu-west-1", region: "eu-west-1", status: "stable", spend: 210 },
  { id: "staging-us-east-2", region: "us-east-2", status: "stable", spend: 180 },
  { id: "sandbox-eu-central-1", region: "eu-central-1", status: "warning", spend: 420 },
  { id: "ml-us-east-1", region: "us-east-1", status: "stable", spend: 1120 },
  { id: "ml-af-south-1", region: "af-south-1", status: "anomaly", spend: 3450 },
  { id: "data-us-west-1", region: "us-west-1", status: "stable", spend: 560 },
  { id: "data-ap-southeast-2", region: "ap-southeast-2", status: "stable", spend: 490 },
  { id: "backup-eu-west-3", region: "eu-west-3", status: "stable", spend: 130 },
  { id: "backup-ca-central-1", region: "ca-central-1", status: "stable", spend: 145 },
  { id: "edge-sa-east-1", region: "sa-east-1", status: "stable", spend: 90 },
  { id: "edge-me-south-1", region: "me-south-1", status: "warning", spend: 260 },
];

const color = (s: Account["status"]) =>
  s === "anomaly" ? "#EF4444" : s === "warning" ? "#F59E0B" : "#10B981";

export function Heatmap({ onAnomalyClick }: { onAnomalyClick?: (a: Account) => void }) {
  const stable = REGIONS.filter(r => r.status === "stable").length;
  const warn = REGIONS.filter(r => r.status === "warning").length;
  const anom = REGIONS.filter(r => r.status === "anomaly").length;

  return (
    <div className="rounded-xl border border-slate-800 bg-[#1E293B]/40 backdrop-blur p-6">
      <div className="flex items-center justify-between mb-5">
        <div>
          <div className="text-[10px] font-mono uppercase tracking-widest text-slate-500">Live · updated 3s ago</div>
          <h3 className="text-lg font-bold">Global Account Overview</h3>
        </div>
        <div className="flex items-center gap-4 text-[11px] font-mono">
          <Legend color="#10B981" label="Stable" count={stable} />
          <Legend color="#F59E0B" label="Warning" count={warn} />
          <Legend color="#EF4444" label="Anomaly" count={anom} />
        </div>
      </div>

      <div className="grid grid-cols-6 md:grid-cols-9 gap-2">
        {REGIONS.map((r, i) => {
          const c = color(r.status);
          const isAnom = r.status === "anomaly";
          return (
            <motion.button
              key={r.id}
              initial={{ opacity: 0, scale: 0.8 }}
              animate={{ opacity: 1, scale: 1 }}
              transition={{ delay: i * 0.02 }}
              onClick={() => isAnom && onAnomalyClick?.(r)}
              className="tt-wrap group relative aspect-square rounded-md border transition-all hover:scale-105 hover:z-10 text-left p-2"
              style={{
                background: `${c}18`,
                borderColor: `${c}55`,
                boxShadow: isAnom ? `0 0 16px ${c}66, inset 0 0 20px ${c}22` : undefined,
              }}
            >
              {isAnom && (
                <motion.span
                  className="absolute inset-0 rounded-md"
                  animate={{ boxShadow: [`0 0 0 0 ${c}00`, `0 0 0 6px ${c}00`] }}
                  style={{ boxShadow: `0 0 0 0 ${c}88` }}
                  transition={{ repeat: Infinity, duration: 1.5 }}
                />
              )}
              <div className="text-[9px] font-mono text-slate-400 truncate">{r.id.split("-")[0]}</div>
              <div className="text-[9px] font-mono truncate" style={{ color: c }}>{r.region}</div>
              <div className="absolute bottom-1 right-1 text-[9px] font-mono font-bold" style={{ color: c }}>
                ${r.spend > 999 ? `${(r.spend/1000).toFixed(1)}k` : r.spend}
              </div>
              <div className="tt">{r.id} · ${r.spend}/day</div>
            </motion.button>
          );
        })}
      </div>
    </div>
  );
}

function Legend({ color, label, count }: { color: string; label: string; count: number }) {
  return (
    <div className="flex items-center gap-1.5">
      <span className="w-2 h-2 rounded-sm" style={{ background: color }} />
      <span className="text-slate-400">{label}</span>
      <span className="font-bold" style={{ color }}>{count}</span>
    </div>
  );
}
