import { useState } from "react";
import { Bar, BarChart, CartesianGrid, Cell, Legend, Line, LineChart, ResponsiveContainer, Tooltip, XAxis, YAxis } from "recharts";
import { useApi } from "../hooks";
import type { Metrics } from "../types";
import { Card, Empty, ErrorNote, Mono, SEVERITY_COLOR, Spinner, fmtMs } from "../components/ui";
import { WindowPicker, bucketLabel } from "./Overview";

interface EvalItem {
  file: string;
  kind: string;
  created_at: string;
  summary: any;
  data: any;
}

const PALETTE = ["#38bdf8", "#34d399", "#fbbf24", "#a78bfa", "#f87171", "#fb923c"];
const pct = (v: number | null | undefined) => (v === null || v === undefined ? "-" : `${(v * 100).toFixed(1)}%`);

function ComparisonTable({ rows, cols }: { rows: { name: string; metrics: Record<string, any> }[]; cols: [string, string, (v: any) => string][] }) {
  return (
    <div className="overflow-x-auto">
      <table className="w-full text-left text-[12.5px]">
        <thead className="text-[11px] tracking-wide text-ink-3 uppercase">
          <tr className="border-b border-line"><th className="py-2 pr-3 font-medium">Configuration</th>{cols.map(([k, label]) => <th key={k} className="px-2 py-2 text-right font-medium">{label}</th>)}</tr>
        </thead>
        <tbody>
          {rows.map((r) => (
            <tr key={r.name} className="border-b border-line/60">
              <td className="py-1.5 pr-3"><Mono className="text-ink">{r.name}</Mono></td>
              {cols.map(([k, , f]) => <td key={k} className="num px-2 py-1.5 text-right font-mono text-ink-2">{f(r.metrics[k])}</td>)}
            </tr>
          ))}
        </tbody>
      </table>
    </div>
  );
}

function FirewallEval({ item }: { item: EvalItem }) {
  const configs: { name: string; metrics: Record<string, any> }[] = item.data.configs ?? [];
  const chart = configs.map((c) => ({ name: c.name, Recall: c.metrics.recall, Precision: c.metrics.precision, FPR: c.metrics.fpr, ASR: c.metrics.asr }));
  return (
    <div className="space-y-4">
      <div className="text-[12px] text-ink-3">
        {item.data.dataset?.name} · {item.data.dataset?.n_samples} held-out samples ({item.data.dataset?.n_attack} attack / {item.data.dataset?.n_benign} benign) ·
        generated {new Date(item.created_at).toLocaleString()} · <Mono>{item.file}</Mono>
      </div>
      <ResponsiveContainer width="100%" height={240}>
        <BarChart data={chart} margin={{ left: -16 }}>
          <CartesianGrid vertical={false} />
          <XAxis dataKey="name" tickLine={false} axisLine={false} />
          <YAxis domain={[0, 1]} tickFormatter={(v) => `${Math.round(v * 100)}%`} tickLine={false} axisLine={false} />
          <Tooltip formatter={(v: number) => pct(v)} />
          <Legend wrapperStyle={{ fontSize: 12 }} />
          <Bar dataKey="Recall" fill="#34d399" radius={[3, 3, 0, 0]} />
          <Bar dataKey="Precision" fill="#38bdf8" radius={[3, 3, 0, 0]} />
          <Bar dataKey="FPR" fill="#fbbf24" radius={[3, 3, 0, 0]} />
          <Bar dataKey="ASR" fill="#f87171" radius={[3, 3, 0, 0]} />
        </BarChart>
      </ResponsiveContainer>
      <ComparisonTable rows={configs} cols={[
        ["precision", "Precision", pct], ["recall", "Recall", pct], ["f1", "F1", (v) => (v == null ? "-" : v.toFixed(3))], ["fpr", "FPR", pct],
        ["fnr", "FNR", pct], ["asr", "ASR", pct], ["policy_violation_rate", "Policy viol.", pct], ["p50_ms", "p50", fmtMs], ["p95_ms", "p95", fmtMs], ["p99_ms", "p99", fmtMs],
      ]} />
    </div>
  );
}

export default function Analytics() {
  const [hours, setHours] = useState(168);
  const m = useApi<Metrics>(`/api/v1/metrics?hours=${hours}`, 15000);
  const ev = useApi<{ items: EvalItem[] }>("/api/v1/evaluations");

  if (!m.data) return m.error ? <ErrorNote error={m.error} /> : <Spinner />;
  const d = m.data;
  const categories = Object.entries(d.categories).filter(([k]) => k !== "none").map(([name, value]) => ({ name, value }));
  const severities = ["low", "medium", "high", "critical"].map((s) => ({ name: s, value: d.severities[s] ?? 0 }));
  const trend = d.timeseries.map((p) => ({ ...p, label: bucketLabel(p.bucket, d.bucket_minutes) }));
  const providers = d.providers.map((p) => ({ name: p.model ? `${p.provider}/${p.model}` : p.provider, avg: p.avg_llm_latency_ms ?? 0, p95: p.p95_llm_latency_ms ?? 0, requests: p.requests, errors: p.errors }));
  const evals = ev.data?.items ?? [];
  const firewall = evals.find((e) => e.kind === "firewall_comparison");
  const detectorsEval = evals.find((e) => e.kind === "detector_eval");
  const experiments = evals.filter((e) => e.kind.startsWith("experiment_"));

  return (
    <div className="space-y-5">
      <div className="flex items-end justify-between">
        <div>
          <h1 className="text-xl font-semibold tracking-tight">Threat analytics</h1>
          <p className="text-sm text-ink-3">Live audit-log analytics plus stored offline evaluation results.</p>
        </div>
        <WindowPicker hours={hours} onChange={setHours} />
      </div>

      <div className="grid gap-4 xl:grid-cols-3">
        <Card title="Threat categories" className="xl:col-span-2">
          {categories.length === 0 ? <Empty>No threats recorded in this window.</Empty> : (
            <ResponsiveContainer width="100%" height={240}>
              <BarChart data={categories} margin={{ left: -16 }}>
                <CartesianGrid vertical={false} />
                <XAxis dataKey="name" tickLine={false} axisLine={false} interval={0} angle={-15} textAnchor="end" height={50} />
                <YAxis allowDecimals={false} tickLine={false} axisLine={false} />
                <Tooltip cursor={{ fill: "rgba(255,255,255,0.03)" }} />
                <Bar dataKey="value" name="Events" radius={[4, 4, 0, 0]}>{categories.map((_, i) => <Cell key={i} fill={PALETTE[i % PALETTE.length]} />)}</Bar>
              </BarChart>
            </ResponsiveContainer>
          )}
        </Card>
        <Card title="Severity distribution">
          <ResponsiveContainer width="100%" height={240}>
            <BarChart data={severities} margin={{ left: -16 }}>
              <CartesianGrid vertical={false} />
              <XAxis dataKey="name" tickLine={false} axisLine={false} />
              <YAxis allowDecimals={false} tickLine={false} axisLine={false} />
              <Tooltip cursor={{ fill: "rgba(255,255,255,0.03)" }} />
              <Bar dataKey="value" name="Events" radius={[4, 4, 0, 0]}>{severities.map((s) => <Cell key={s.name} fill={SEVERITY_COLOR[s.name]} />)}</Bar>
            </BarChart>
          </ResponsiveContainer>
        </Card>
      </div>

      <Card title="Detection trend">
        {trend.length === 0 ? <Empty>No data.</Empty> : (
          <ResponsiveContainer width="100%" height={220}>
            <LineChart data={trend} margin={{ left: -16, right: 8 }}>
              <CartesianGrid vertical={false} />
              <XAxis dataKey="label" tickLine={false} axisLine={false} minTickGap={24} />
              <YAxis allowDecimals={false} tickLine={false} axisLine={false} />
              <Tooltip />
              <Legend wrapperStyle={{ fontSize: 12 }} />
              <Line type="monotone" dataKey="threats" name="Threats" stroke="#fbbf24" dot={false} strokeWidth={2} />
              <Line type="monotone" dataKey="blocked" name="Blocked" stroke="#f87171" dot={false} strokeWidth={2} />
              <Line type="monotone" dataKey="redacted" name="Redacted" stroke="#a78bfa" dot={false} strokeWidth={2} />
            </LineChart>
          </ResponsiveContainer>
        )}
      </Card>

      <div className="grid gap-4 xl:grid-cols-2">
        <Card title="Detector activity (live)" pad={false}>
          <table className="w-full text-left text-[12.5px]">
            <thead className="text-[11px] tracking-wide text-ink-3 uppercase">
              <tr className="border-b border-line"><th className="px-4 py-2 font-medium">Stage · detector</th><th className="px-2 py-2 text-right font-medium">Runs</th>
                <th className="px-2 py-2 text-right font-medium">Hit rate</th><th className="px-2 py-2 text-right font-medium">Failures</th>
                <th className="px-2 py-2 text-right font-medium">Avg</th><th className="px-4 py-2 text-right font-medium">p95</th></tr>
            </thead>
            <tbody>
              {d.detectors.map((x) => (
                <tr key={`${x.stage}:${x.detector}`} className="border-b border-line/60">
                  <td className="px-4 py-1.5"><span className="text-ink-3">{x.stage} · </span><Mono className="text-ink">{x.detector}</Mono></td>
                  <td className="num px-2 py-1.5 text-right font-mono">{x.runs}</td>
                  <td className="num px-2 py-1.5 text-right font-mono">{pct(x.runs ? x.detections / x.runs : null)}</td>
                  <td className={"num px-2 py-1.5 text-right font-mono " + (x.failures ? "text-block" : "")}>{x.failures}</td>
                  <td className="num px-2 py-1.5 text-right font-mono text-ink-2">{fmtMs(x.avg_latency_ms)}</td>
                  <td className="num px-4 py-1.5 text-right font-mono text-ink-2">{fmtMs(x.p95_latency_ms)}</td>
                </tr>
              ))}
              {d.detectors.length === 0 && <tr><td colSpan={6}><Empty>No detector runs.</Empty></td></tr>}
            </tbody>
          </table>
        </Card>
        <Card title="Provider comparison (LLM latency)">
          {providers.length === 0 ? <Empty>No LLM calls in this window.</Empty> : (
            <>
              <ResponsiveContainer width="100%" height={180}>
                <BarChart data={providers} margin={{ left: -8 }}>
                  <CartesianGrid vertical={false} />
                  <XAxis dataKey="name" tickLine={false} axisLine={false} />
                  <YAxis tickFormatter={(v) => `${(v / 1000).toFixed(1)}s`} tickLine={false} axisLine={false} />
                  <Tooltip formatter={(v: number) => fmtMs(v)} />
                  <Legend wrapperStyle={{ fontSize: 12 }} />
                  <Bar dataKey="avg" name="avg" fill="#38bdf8" radius={[3, 3, 0, 0]} />
                  <Bar dataKey="p95" name="p95" fill="#a78bfa" radius={[3, 3, 0, 0]} />
                </BarChart>
              </ResponsiveContainer>
              <div className="mt-2 grid grid-cols-2 gap-2 text-[12px] text-ink-3">
                {providers.map((p) => <div key={p.name}><Mono className="text-ink-2">{p.name}</Mono>: {p.requests} requests · {p.errors} errors</div>)}
              </div>
            </>
          )}
        </Card>
      </div>

      <Card title="False-positive measurements">
        <div className="grid gap-4 md:grid-cols-3">
          <div>
            <div className="text-[12px] text-ink-3 uppercase">Observed (operator reviews)</div>
            <div className="num mt-1 text-2xl font-semibold">{pct(d.reviews.observed_false_positive_rate)}</div>
            <div className="text-[12px] text-ink-3">{d.reviews.counts.false_positive ?? 0} false / {d.reviews.counts.true_positive ?? 0} true positives labelled in the Event Explorer</div>
          </div>
          <div className="md:col-span-2">
            <div className="text-[12px] text-ink-3 uppercase">Offline benchmark FPR on benign prompts</div>
            {firewall ? (
              <div className="mt-2 flex flex-wrap gap-2">
                {firewall.data.configs.map((c: any) => (
                  <div key={c.name} className="rounded-lg border border-line bg-canvas px-3 py-1.5 text-[12.5px]"><Mono>{c.name}</Mono>: <b className="num">{pct(c.metrics.fpr)}</b></div>
                ))}
              </div>
            ) : <div className="mt-1 text-sm text-ink-3">Run <Mono>experiments/evaluate_firewall.py</Mono> to populate.</div>}
          </div>
        </div>
      </Card>

      <Card title="Firewall evaluation (held-out set)">
        {ev.error ? <ErrorNote error={ev.error} /> : firewall ? <FirewallEval item={firewall} /> : <Empty>No evaluation results stored yet.</Empty>}
      </Card>

      {detectorsEval && (
        <Card title="Per-detector evaluation (rules vs ML vs hybrid)">
          <ComparisonTable rows={detectorsEval.data.rows.map((r: any) => ({ name: `${r.detector} · ${r.mode}`, metrics: r.metrics }))} cols={[
            ["precision", "Precision", pct], ["recall", "Recall", pct], ["f1", "F1", (v) => (v == null ? "-" : v.toFixed(3))], ["fpr", "FPR", pct], ["p95_ms", "p95", fmtMs],
          ]} />
        </Card>
      )}

      {experiments.length > 0 && (
        <Card title="Research experiments">
          <div className="space-y-5">
            {experiments.map((e) => (
              <div key={e.file}>
                <div className="mb-1.5 flex items-center justify-between text-[13px]"><span className="font-semibold text-ink">{e.data.title ?? e.kind}</span><Mono className="text-ink-3">{e.file}</Mono></div>
                {e.data.description && <p className="mb-2 text-[12px] text-ink-3">{e.data.description}</p>}
                <ComparisonTable rows={e.data.configs ?? []} cols={(e.data.columns ?? []).map((c: string) => [c, c.replace(/_/g, " "), (v: any) => {
                  if (typeof v !== "number") return String(v ?? "-");
                  if (c.endsWith("_ms")) return fmtMs(v);
                  if (c.startsWith("n_") || c.endsWith("_calls") || c.endsWith("_tokens")) return v.toLocaleString();
                  if (c.startsWith("est_cost")) return `$${v.toFixed(4)}`;
                  return pct(v);
                }])} />
              </div>
            ))}
          </div>
        </Card>
      )}
    </div>
  );
}
