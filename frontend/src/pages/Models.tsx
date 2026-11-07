import { Cloud, Cpu, HardDrive, RefreshCw, ShieldQuestion } from "lucide-react";
import { useApi } from "../hooks";
import { Card, Empty, ErrorNote, Mono, Spinner, btnGhost, cx, fmtMs } from "../components/ui";

interface ModelsResponse {
  providers: { provider: string; provider_type: string; is_local: boolean; status: string; latency_ms: number | null; detail: string; models: string[]; default_model: string | null }[];
  cloud: { enabled: boolean; configured: boolean; base_url_host: string | null; api_key_present: boolean; fallback_enabled_env: boolean; fallback_enabled_policy: boolean };
  classifiers: { name: string; model_id: string; backend: string; available: boolean; error: string | null; load_seconds: number | null; labels: string[]; positive_labels: string[] }[];
  pii: { engine: string; spacy_model: string; error: string | null; supported_entities: string[] };
  observed_latency_24h: { provider: string; model: string; calls: number; avg_latency_ms: number | null }[];
  verification: { enabled: boolean; provider: string; resolved_model: string | null; model_installed: boolean | null; install_hint: string | null; provider_status: string; on_unavailable: string; min_confidence_to_escalate: number };
}

const STATUS_COLOR: Record<string, string> = {
  ok: "var(--color-allow)", degraded: "var(--color-redact)", unavailable: "var(--color-block)", unconfigured: "var(--color-ink-3)", disabled: "var(--color-ink-3)",
};

function Status({ status }: { status: string }) {
  const c = STATUS_COLOR[status] ?? "var(--color-ink-3)";
  return <span className="inline-flex items-center gap-1.5 text-[12px] font-medium" style={{ color: c }}><span className="h-2 w-2 rounded-full" style={{ background: c }} />{status}</span>;
}

export default function Models() {
  const { data, error, loading, reload } = useApi<ModelsResponse>("/api/v1/models", 30000);
  if (!data) return error ? <ErrorNote error={error} /> : <Spinner />;
  const latency = (p: string) => data.observed_latency_24h.filter((l) => l.provider === p);

  return (
    <div className="space-y-5">
      <div className="flex items-end justify-between">
        <div>
          <h1 className="text-xl font-semibold tracking-tight">Model configuration</h1>
          <p className="text-sm text-ink-3">LLM providers, local detection models and their health. API secrets are never sent to this page.</p>
        </div>
        <button className={btnGhost} onClick={reload}><RefreshCw className={cx("h-3.5 w-3.5", loading && "animate-spin")} /> Re-check</button>
      </div>

      <div className="grid gap-4 lg:grid-cols-2">
        {data.providers.map((p) => (
          <Card key={p.provider} title={<span className="flex items-center gap-2">{p.is_local ? <HardDrive className="h-4 w-4" /> : <Cloud className="h-4 w-4" />}{p.provider}</span>}
            actions={<Status status={p.status} />}>
            <div className="grid grid-cols-2 gap-3 text-[13px]">
              <div><div className="text-[11px] text-ink-3 uppercase">Type</div>{p.provider_type} · {p.is_local ? "local" : "cloud / remote"}</div>
              <div><div className="text-[11px] text-ink-3 uppercase">Health check</div>{fmtMs(p.latency_ms)}</div>
              <div><div className="text-[11px] text-ink-3 uppercase">Default model</div><Mono>{p.default_model ?? "-"}</Mono></div>
              <div><div className="text-[11px] text-ink-3 uppercase">Inference (24h avg)</div>
                {latency(p.provider).length ? latency(p.provider).map((l) => <div key={l.model}><Mono className="text-ink-2">{l.model}</Mono> {fmtMs(l.avg_latency_ms)} <span className="text-ink-3">({l.calls})</span></div>) : <span className="text-ink-3">no calls</span>}
              </div>
            </div>
            {p.detail && <div className="mt-3 rounded-lg border border-redact/30 bg-redact/5 px-3 py-2 text-[12px] text-redact">{p.detail}</div>}
            <div className="mt-3 text-[11px] text-ink-3 uppercase">Available models</div>
            <div className="mt-1 flex flex-wrap gap-1.5">{p.models.length ? p.models.map((m) => (
              <span key={m} className={cx("rounded-md border px-1.5 py-0.5 font-mono text-[11px]", m === p.default_model ? "border-accent/50 text-accent" : "border-line text-ink-2")}>{m}</span>
            )) : <span className="text-[12px] text-ink-3">none reported</span>}</div>
          </Card>
        ))}
        {data.providers.length === 0 && <Card><Empty>No providers configured. Set SENTINEL_OLLAMA_ENABLED or SENTINEL_CLOUD_ENABLED.</Empty></Card>}
      </div>

      <div className="grid gap-4 lg:grid-cols-2">
        <Card title={<span className="flex items-center gap-2"><Cloud className="h-4 w-4" /> Cloud provider configuration</span>}>
          <dl className="grid grid-cols-2 gap-y-2 text-[13px]">
            <dt className="text-ink-3">Enabled</dt><dd>{data.cloud.enabled ? "yes" : "no"}</dd>
            <dt className="text-ink-3">Configured</dt><dd>{data.cloud.configured ? "yes" : "no"}</dd>
            <dt className="text-ink-3">Endpoint host</dt><dd><Mono>{data.cloud.base_url_host ?? "-"}</Mono></dd>
            <dt className="text-ink-3">API key present</dt><dd>{data.cloud.api_key_present ? "yes (value never exposed)" : "no"}</dd>
            <dt className="text-ink-3">Cloud fallback</dt><dd>env {data.cloud.fallback_enabled_env ? "on" : "off"} · policy {data.cloud.fallback_enabled_policy ? "on" : "off"}</dd>
          </dl>
        </Card>
        <Card title={<span className="flex items-center gap-2"><ShieldQuestion className="h-4 w-4" /> Secondary verifier</span>} actions={<Status status={data.verification.enabled ? (data.verification.model_installed === false ? "degraded" : data.verification.provider_status) : "disabled"} />}>
          <dl className="grid grid-cols-2 gap-y-2 text-[13px]">
            <dt className="text-ink-3">Provider / model</dt><dd><Mono>{data.verification.provider} / {data.verification.resolved_model ?? "-"}</Mono></dd>
            <dt className="text-ink-3">Model installed</dt><dd>{data.verification.model_installed === null ? "unknown" : data.verification.model_installed ? "yes" : "no"}</dd>
            <dt className="text-ink-3">Escalation confidence</dt><dd className="num">{data.verification.min_confidence_to_escalate}</dd>
            <dt className="text-ink-3">If unavailable</dt><dd>{data.verification.on_unavailable}</dd>
          </dl>
          {data.verification.install_hint && <div className="mt-3 rounded-lg border border-redact/30 bg-redact/5 px-3 py-2 font-mono text-[12px] text-redact">{data.verification.install_hint}</div>}
        </Card>
      </div>

      <Card title={<span className="flex items-center gap-2"><Cpu className="h-4 w-4" /> Local detection models</span>} pad={false}>
        <table className="w-full text-left text-[13px]">
          <thead className="text-[11px] tracking-wide text-ink-3 uppercase"><tr className="border-b border-line">
            <th className="px-4 py-2 font-medium">Role</th><th className="px-2 py-2 font-medium">Model</th><th className="px-2 py-2 font-medium">Backend</th>
            <th className="px-2 py-2 font-medium">Status</th><th className="px-2 py-2 font-medium">Positive labels</th><th className="px-4 py-2 text-right font-medium">Load time</th></tr></thead>
          <tbody>
            {data.classifiers.map((c) => (
              <tr key={c.name} className="border-b border-line/60">
                <td className="px-4 py-2"><Mono className="text-ink">{c.name}</Mono></td>
                <td className="px-2 py-2"><Mono className="text-ink-2">{c.model_id}</Mono>{c.error && <div className="text-[11px] text-block">{c.error}</div>}</td>
                <td className="px-2 py-2 text-ink-2">{c.backend}</td>
                <td className="px-2 py-2"><Status status={c.available ? "ok" : "unavailable"} /></td>
                <td className="px-2 py-2 font-mono text-[11px] text-ink-3">{c.positive_labels.join(", ")}</td>
                <td className="num px-4 py-2 text-right font-mono text-[12px] text-ink-2">{c.load_seconds != null ? `${c.load_seconds}s` : "-"}</td>
              </tr>
            ))}
            <tr>
              <td className="px-4 py-2"><Mono className="text-ink">pii</Mono></td>
              <td className="px-2 py-2"><Mono className="text-ink-2">presidio + spaCy {data.pii.spacy_model}</Mono>{data.pii.error && <div className="text-[11px] text-block">{data.pii.error}</div>}</td>
              <td className="px-2 py-2 text-ink-2">{data.pii.engine}</td>
              <td className="px-2 py-2"><Status status={data.pii.engine === "presidio" ? "ok" : "degraded"} /></td>
              <td className="px-2 py-2 text-[11px] text-ink-3" colSpan={2}>{data.pii.supported_entities.length} entity types</td>
            </tr>
          </tbody>
        </table>
      </Card>
    </div>
  );
}
