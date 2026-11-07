import { useState } from "react";
import { Link } from "react-router-dom";
import { Area, AreaChart, Bar, BarChart, CartesianGrid, Cell, ResponsiveContainer, Tooltip, XAxis, YAxis } from "recharts";
import { Ban, Clock, EyeOff, Gauge, ShieldAlert, UserCheck } from "lucide-react";
import { useApi } from "../hooks";
import type { Metrics } from "../types";
import { Card, DECISION_COLOR, DecisionBadge, Empty, ErrorNote, SeverityBadge, Spinner, Stat, cx, fmtMs, fmtTime } from "../components/ui";

export const WINDOWS = [
  { label: "1h", hours: 1 },
  { label: "24h", hours: 24 },
  { label: "7d", hours: 168 },
  { label: "30d", hours: 720 },
];

export function WindowPicker({ hours, onChange }: { hours: number; onChange: (h: number) => void }) {
  return (
    <div className="flex rounded-lg border border-line bg-panel p-0.5">
      {WINDOWS.map((w) => (
        <button key={w.hours} onClick={() => onChange(w.hours)}
          className={cx("rounded-md px-2.5 py-1 text-[12px] font-medium", w.hours === hours ? "bg-panel-2 text-ink" : "text-ink-3 hover:text-ink")}>
          {w.label}
        </button>
      ))}
    </div>
  );
}

export function bucketLabel(iso: string, minutes: number): string {
  const d = new Date(iso);
  return minutes >= 360
    ? d.toLocaleDateString(undefined, { month: "short", day: "numeric" }) + " " + d.getHours() + "h"
    : d.toLocaleTimeString(undefined, { hour: "2-digit", minute: "2-digit" });
}

export default function Overview() {
  const [hours, setHours] = useState(24);
  const { data, error, loading } = useApi<Metrics>(`/api/v1/metrics?hours=${hours}`, 10000);

  if (!data) return error ? <ErrorNote error={error} /> : <Spinner />;
  const t = data.totals;
  const decisions = ["ALLOW", "REDACT", "VERIFY", "HUMAN_REVIEW", "BLOCK"].map((d) => ({ name: d, value: data.decisions[d] ?? 0 }));
  const series = data.timeseries.map((p) => ({ ...p, label: bucketLabel(p.bucket, data.bucket_minutes) }));
  const allowShare = t.requests ? Math.round(((data.decisions.ALLOW ?? 0) / t.requests) * 100) : 0;

  return (
    <div className="space-y-5">
      <div className="flex items-end justify-between">
        <div>
          <h1 className="text-xl font-semibold tracking-tight">Security overview</h1>
          <p className="text-sm text-ink-3">Live gateway activity from the audit log · refreshes every 10 s {loading && "· updating"}</p>
        </div>
        <WindowPicker hours={hours} onChange={setHours} />
      </div>

      <div className="grid grid-cols-2 gap-3 md:grid-cols-3 xl:grid-cols-6">
        <Stat label="Requests" value={t.requests.toLocaleString()} sub={`${allowShare}% allowed`} icon={<Gauge className="h-4 w-4" />} />
        <Stat label="Threats" value={t.threats_detected.toLocaleString()} tone="var(--color-redact)" icon={<ShieldAlert className="h-4 w-4" />}
          sub="injection, jailbreak, secrets, toxicity, tools" />
        <Stat label="Blocked" value={t.blocked.toLocaleString()} tone="var(--color-block)" icon={<Ban className="h-4 w-4" />}
          sub={t.requests ? `${((t.blocked / t.requests) * 100).toFixed(1)}% of traffic` : "-"} />
        <Stat label="PII redactions" value={t.pii_redactions.toLocaleString()} tone="var(--color-redact)" icon={<EyeOff className="h-4 w-4" />} sub="requests forwarded with placeholders" />
        <Stat label="Human review" value={t.human_review.toLocaleString()} tone="var(--color-review)" icon={<UserCheck className="h-4 w-4" />} sub="held for an operator" />
        <Stat label="Latency p50 / p95" value={<span className="text-[20px]">{fmtMs(t.p50_latency_ms)} <span className="text-ink-3">/</span> {fmtMs(t.p95_latency_ms)}</span>}
          icon={<Clock className="h-4 w-4" />} sub={`avg ${fmtMs(t.avg_latency_ms)} end-to-end`} />
      </div>

      <div className="grid gap-4 xl:grid-cols-3">
        <Card title="Traffic and threats" className="xl:col-span-2">
          {series.length === 0 ? <Empty>No traffic in this window. Send a prompt from the Request Inspector.</Empty> : (
            <ResponsiveContainer width="100%" height={240}>
              <AreaChart data={series} margin={{ left: -18, right: 8, top: 8 }}>
                <defs>
                  <linearGradient id="gTotal" x1="0" x2="0" y1="0" y2="1"><stop offset="0%" stopColor="#38bdf8" stopOpacity={0.35} /><stop offset="100%" stopColor="#38bdf8" stopOpacity={0} /></linearGradient>
                  <linearGradient id="gBlock" x1="0" x2="0" y1="0" y2="1"><stop offset="0%" stopColor="#f87171" stopOpacity={0.35} /><stop offset="100%" stopColor="#f87171" stopOpacity={0} /></linearGradient>
                </defs>
                <CartesianGrid vertical={false} />
                <XAxis dataKey="label" tickLine={false} axisLine={false} minTickGap={24} />
                <YAxis allowDecimals={false} tickLine={false} axisLine={false} />
                <Tooltip />
                <Area type="monotone" dataKey="total" name="Requests" stroke="#38bdf8" fill="url(#gTotal)" strokeWidth={2} />
                <Area type="monotone" dataKey="threats" name="Threats" stroke="#fbbf24" fill="transparent" strokeWidth={1.5} />
                <Area type="monotone" dataKey="blocked" name="Blocked" stroke="#f87171" fill="url(#gBlock)" strokeWidth={1.5} />
              </AreaChart>
            </ResponsiveContainer>
          )}
        </Card>
        <Card title="Decision distribution">
          <ResponsiveContainer width="100%" height={240}>
            <BarChart data={decisions} layout="vertical" margin={{ left: 20, right: 24 }}>
              <XAxis type="number" hide allowDecimals={false} />
              <YAxis type="category" dataKey="name" tickLine={false} axisLine={false} width={96} />
              <Tooltip cursor={{ fill: "rgba(255,255,255,0.03)" }} />
              <Bar dataKey="value" name="Requests" radius={[0, 4, 4, 0]} barSize={18} label={{ position: "right", fill: "#a3aec0", fontSize: 11 }}>
                {decisions.map((d) => <Cell key={d.name} fill={DECISION_COLOR[d.name]} />)}
              </Bar>
            </BarChart>
          </ResponsiveContainer>
        </Card>
      </div>

      <Card title="Recent security events" actions={<Link to="/events" className="text-[12px] text-accent hover:underline">Open explorer</Link>} pad={false}>
        {data.recent_events.length === 0 ? <Empty>No events yet.</Empty> : (
          <div className="overflow-x-auto">
            <table className="w-full text-left text-[13px]">
              <thead className="text-[11px] tracking-wide text-ink-3 uppercase">
                <tr className="border-b border-line">
                  <th className="px-4 py-2 font-medium">Time</th><th className="px-2 py-2 font-medium">Type</th><th className="px-2 py-2 font-medium">Decision</th>
                  <th className="px-2 py-2 font-medium">Category</th><th className="px-2 py-2 font-medium">Severity</th><th className="px-2 py-2 font-medium">Risk</th>
                  <th className="px-2 py-2 font-medium">Preview (redacted)</th><th className="px-4 py-2 text-right font-medium">Latency</th>
                </tr>
              </thead>
              <tbody>
                {data.recent_events.map((e) => (
                  <tr key={e.request_id} className="border-b border-line/60 hover:bg-panel-2">
                    <td className="px-4 py-2 whitespace-nowrap text-ink-2">{fmtTime(e.timestamp)}</td>
                    <td className="px-2 py-2 text-ink-2">{e.event_type}</td>
                    <td className="px-2 py-2"><DecisionBadge decision={e.output_decision === "BLOCK" ? "BLOCK" : e.decision} /></td>
                    <td className="px-2 py-2 font-mono text-[12px] text-ink-2">{e.threat_category}</td>
                    <td className="px-2 py-2"><SeverityBadge severity={e.severity} /></td>
                    <td className="num px-2 py-2 font-mono text-[12px]">{e.risk_score.toFixed(2)}</td>
                    <td className="max-w-[380px] truncate px-2 py-2 text-ink-3">{e.preview ?? "-"}</td>
                    <td className="num px-4 py-2 text-right font-mono text-[12px] text-ink-2">{fmtMs(e.latency_ms)}</td>
                  </tr>
                ))}
              </tbody>
            </table>
          </div>
        )}
      </Card>
    </div>
  );
}
