import { useEffect, useState } from "react";
import { ChevronLeft, ChevronRight, RefreshCw, Search, X } from "lucide-react";
import { ApiError, api } from "../api";
import { useApi } from "../hooks";
import type { EventDetail, EventRow } from "../types";
import {
  Card, DecisionBadge, Empty, ErrorNote, JsonBlock, Mono, RedactedText, ScoreBar, SeverityBadge, Spinner, btnGhost, cx, fmtMs, fmtTime, inputCls,
} from "../components/ui";

interface Page { items: EventRow[]; total: number; limit: number; offset: number }

const LIMIT = 25;

function Drawer({ requestId, onClose, onChanged }: { requestId: string; onClose: () => void; onChanged: () => void }) {
  const { data, error, reload } = useApi<EventDetail>(`/api/v1/events/${encodeURIComponent(requestId)}`);
  const [busy, setBusy] = useState(false);
  const [err, setErr] = useState<ApiError | null>(null);

  async function review(status: string) {
    setBusy(true);
    setErr(null);
    try {
      await api.post(`/api/v1/events/${encodeURIComponent(requestId)}/review`, { status });
      reload();
      onChanged();
    } catch (e) {
      setErr(e as ApiError);
    } finally {
      setBusy(false);
    }
  }

  return (
    <div className="fixed inset-0 z-40 flex justify-end bg-black/50" onClick={onClose}>
      <div className="h-full w-full max-w-3xl overflow-y-auto border-l border-line bg-panel p-5" onClick={(e) => e.stopPropagation()}>
        <div className="flex items-start justify-between">
          <div>
            <div className="text-[12px] text-ink-3 uppercase">Security event</div>
            <Mono className="text-ink">{requestId}</Mono>
          </div>
          <button onClick={onClose} className="rounded-md p-1 text-ink-3 hover:bg-panel-2 hover:text-ink" aria-label="Close"><X className="h-5 w-5" /></button>
        </div>
        {error && <div className="mt-4"><ErrorNote error={error} /></div>}
        {!data && !error && <div className="mt-6"><Spinner /></div>}
        {data && (
          <div className="mt-4 space-y-4">
            <div className="grid grid-cols-2 gap-3 text-[13px] sm:grid-cols-4">
              <div><div className="text-[11px] text-ink-3 uppercase">Decision</div><DecisionBadge decision={data.decision} /></div>
              <div><div className="text-[11px] text-ink-3 uppercase">Output</div><DecisionBadge decision={data.output_decision} /></div>
              <div><div className="text-[11px] text-ink-3 uppercase">Severity</div><SeverityBadge severity={data.severity} /></div>
              <div><div className="text-[11px] text-ink-3 uppercase">Risk</div><ScoreBar value={data.risk_score} width={70} /></div>
              <div><div className="text-[11px] text-ink-3 uppercase">Type</div>{data.event_type}</div>
              <div><div className="text-[11px] text-ink-3 uppercase">Provider</div>{data.provider ?? "-"}{data.model && <span className="text-ink-3"> / {data.model}</span>}</div>
              <div><div className="text-[11px] text-ink-3 uppercase">Latency</div>{fmtMs(data.processing_latency)}</div>
              <div><div className="text-[11px] text-ink-3 uppercase">Policy</div>v{data.policy_version}</div>
            </div>
            <div>
              <div className="text-[11px] text-ink-3 uppercase">Categories</div>
              <div className="mt-1 flex flex-wrap gap-1.5">{data.threat_categories.length ? data.threat_categories.map((c) => (
                <span key={c} className="rounded-md border border-line px-1.5 py-0.5 font-mono text-[11px] text-ink-2">{c}</span>)) : <span className="text-ink-3 text-sm">none</span>}</div>
            </div>
            <div>
              <div className="text-[11px] text-ink-3 uppercase">Stored preview (redacted, truncated)</div>
              <div className="mt-1 rounded-lg border border-line bg-canvas p-3 text-[13px]">{data.input_preview ? <RedactedText text={data.input_preview} /> : <span className="text-ink-3">Not stored</span>}</div>
            </div>
            <div className="flex flex-wrap items-center gap-2">
              <span className="text-[12px] text-ink-3">Review: <b className="text-ink-2">{data.review_status ?? "none"}</b></span>
              {[["true_positive", "True positive"], ["false_positive", "False positive"], ["approved", "Approve"], ["rejected", "Reject"]].map(([s, l]) => (
                <button key={s} disabled={busy} className={btnGhost} onClick={() => review(s)}>{l}</button>
              ))}
            </div>
            <ErrorNote error={err} />
            <Card title="Detector results" pad={false}>
              <table className="w-full text-left text-[12.5px]">
                <thead className="text-[11px] text-ink-3 uppercase"><tr className="border-b border-line">
                  <th className="px-3 py-2 font-medium">Stage</th><th className="px-2 py-2 font-medium">Detector</th><th className="px-2 py-2 font-medium">Score</th>
                  <th className="px-2 py-2 font-medium">Status</th><th className="px-3 py-2 font-medium">Reason</th></tr></thead>
                <tbody>
                  {data.detections.map((d, i) => (
                    <tr key={i} className="border-b border-line/60 align-top">
                      <td className="px-3 py-1.5 text-ink-3">{d.stage}</td>
                      <td className="px-2 py-1.5"><Mono className={d.detected ? "text-block" : "text-ink"}>{d.detector}</Mono></td>
                      <td className="px-2 py-1.5"><ScoreBar value={d.score} width={60} /></td>
                      <td className="px-2 py-1.5 text-ink-2">{d.method} · {d.status}</td>
                      <td className="px-3 py-1.5 text-ink-2">{d.reason}</td>
                    </tr>
                  ))}
                </tbody>
              </table>
            </Card>
            <div>
              <div className="mb-1 text-[11px] text-ink-3 uppercase">Decision metadata (sanitized)</div>
              <JsonBlock value={data.detector_metadata} maxHeight={420} />
            </div>
          </div>
        )}
      </div>
    </div>
  );
}

export default function Events() {
  const [q, setQ] = useState("");
  const [query, setQuery] = useState("");
  const [decision, setDecision] = useState("");
  const [severity, setSeverity] = useState("");
  const [eventType, setEventType] = useState("");
  const [category, setCategory] = useState("");
  const [review, setReview] = useState("");
  const [offset, setOffset] = useState(0);
  const [selected, setSelected] = useState<string | null>(null);

  useEffect(() => setOffset(0), [query, decision, severity, eventType, category, review]);

  const params = new URLSearchParams({ limit: String(LIMIT), offset: String(offset) });
  if (query) params.set("q", query);
  if (decision) params.set("decision", decision);
  if (severity) params.set("severity", severity);
  if (eventType) params.set("event_type", eventType);
  if (category) params.set("category", category);
  if (review) params.set("review_status", review);
  const { data, error, loading, reload } = useApi<Page>(`/api/v1/events?${params.toString()}`, 15000);

  const sel = (value: string, set: (v: string) => void, opts: string[], label: string) => (
    <select className="rounded-lg border border-line-strong bg-canvas px-2.5 py-1.5 text-sm text-ink focus:border-accent focus:outline-none" value={value} onChange={(e) => set(e.target.value)} aria-label={label}>
      <option value="">{label}: all</option>
      {opts.map((o) => <option key={o} value={o}>{o}</option>)}
    </select>
  );

  return (
    <div className="space-y-5">
      <div className="flex items-end justify-between">
        <div>
          <h1 className="text-xl font-semibold tracking-tight">Security event explorer</h1>
          <p className="text-sm text-ink-3">Every decision is audited. Raw prompts are not stored by default; previews are redacted and truncated.</p>
        </div>
        <button className={btnGhost} onClick={reload}><RefreshCw className={cx("h-3.5 w-3.5", loading && "animate-spin")} /> Refresh</button>
      </div>

      <Card>
        <form className="flex flex-wrap items-center gap-2" onSubmit={(e) => { e.preventDefault(); setQuery(q.trim()); }}>
          <div className="relative min-w-[240px] flex-1">
            <Search className="absolute top-2.5 left-2.5 h-4 w-4 text-ink-3" />
            <input className={cx(inputCls, "pl-8")} placeholder="Search request id, session or preview" value={q} onChange={(e) => setQ(e.target.value)} />
          </div>
          {sel(decision, setDecision, ["ALLOW", "REDACT", "HUMAN_REVIEW", "BLOCK"], "Decision")}
          {sel(severity, setSeverity, ["none", "low", "medium", "high", "critical"], "Severity")}
          {sel(eventType, setEventType, ["chat", "input", "output", "context", "tool"], "Type")}
          {sel(category, setCategory, ["prompt_injection", "jailbreak", "pii", "secret", "toxicity", "indirect_injection", "tool_abuse"], "Category")}
          {sel(review, setReview, ["pending", "true_positive", "false_positive", "approved", "rejected"], "Review")}
        </form>
      </Card>

      <Card pad={false}>
        {error && <div className="p-4"><ErrorNote error={error} /></div>}
        {!data && !error && <div className="p-4"><Spinner /></div>}
        {data && (data.items.length === 0 ? <Empty>No matching events.</Empty> : (
          <div className="overflow-x-auto">
            <table className="w-full text-left text-[13px]">
              <thead className="text-[11px] tracking-wide text-ink-3 uppercase">
                <tr className="border-b border-line">
                  <th className="px-4 py-2 font-medium">Time</th><th className="px-2 py-2 font-medium">Request</th><th className="px-2 py-2 font-medium">Type</th>
                  <th className="px-2 py-2 font-medium">Decision</th><th className="px-2 py-2 font-medium">Category</th><th className="px-2 py-2 font-medium">Severity</th>
                  <th className="px-2 py-2 font-medium">Risk</th><th className="px-2 py-2 font-medium">Preview</th><th className="px-4 py-2 text-right font-medium">Latency</th>
                </tr>
              </thead>
              <tbody>
                {data.items.map((e) => (
                  <tr key={e.request_id} onClick={() => setSelected(e.request_id)} className="cursor-pointer border-b border-line/60 hover:bg-panel-2">
                    <td className="px-4 py-2 whitespace-nowrap text-ink-2">{fmtTime(e.timestamp)}</td>
                    <td className="px-2 py-2"><Mono className="text-ink-3">{e.request_id.slice(0, 14)}…</Mono></td>
                    <td className="px-2 py-2 text-ink-2">{e.event_type}</td>
                    <td className="px-2 py-2"><DecisionBadge decision={e.output_decision === "BLOCK" ? "BLOCK" : e.decision} /></td>
                    <td className="px-2 py-2 font-mono text-[12px] text-ink-2">{e.threat_category}</td>
                    <td className="px-2 py-2"><SeverityBadge severity={e.severity} /></td>
                    <td className="num px-2 py-2 font-mono text-[12px]">{e.risk_score.toFixed(2)}</td>
                    <td className="max-w-[340px] truncate px-2 py-2 text-ink-3">{e.input_preview ?? "-"}</td>
                    <td className="num px-4 py-2 text-right font-mono text-[12px] text-ink-2">{fmtMs(e.processing_latency)}</td>
                  </tr>
                ))}
              </tbody>
            </table>
          </div>
        ))}
        {data && data.total > 0 && (
          <div className="flex items-center justify-between border-t border-line px-4 py-2 text-[12px] text-ink-3">
            <span className="num">{data.offset + 1}-{Math.min(data.offset + data.items.length, data.total)} of {data.total}</span>
            <div className="flex gap-1.5">
              <button className={btnGhost} disabled={offset === 0} onClick={() => setOffset(Math.max(0, offset - LIMIT))}><ChevronLeft className="h-3.5 w-3.5" /></button>
              <button className={btnGhost} disabled={offset + LIMIT >= data.total} onClick={() => setOffset(offset + LIMIT)}><ChevronRight className="h-3.5 w-3.5" /></button>
            </div>
          </div>
        )}
      </Card>
      {selected && <Drawer requestId={selected} onClose={() => setSelected(null)} onChanged={reload} />}
    </div>
  );
}
