import { useEffect, useMemo, useState, type ReactNode } from "react";
import { Braces, History, RotateCcw, Save } from "lucide-react";
import { ApiError, api } from "../api";
import { useApi } from "../hooks";
import { Card, ErrorNote, Mono, Spinner, Toggle, btnGhost, btnPrimary, cx, fmtTime, inputCls } from "../components/ui";

interface PolicyResponse {
  version: number;
  hash: string;
  sections: string[];
  policy: Record<string, any>;
  providers_configured: string[];
  recent_changes: { timestamp: string; actor: string; section: string; from_version: number; to_version: number; comment: string | null }[];
}

const ACTIONS = ["ALLOW", "REDACT", "VERIFY", "HUMAN_REVIEW", "BLOCK"];
const clone = <T,>(v: T): T => JSON.parse(JSON.stringify(v));

function Field({ label, hint, children }: { label: string; hint?: string; children: ReactNode }) {
  return (
    <label className="block text-[12.5px]">
      <span className="text-ink-2">{label}</span>
      {hint && <span className="ml-1 text-[11px] text-ink-3">· {hint}</span>}
      <div className="mt-1">{children}</div>
    </label>
  );
}

function Slider({ value, onChange, min = 0, max = 1, step = 0.01 }: { value: number; onChange: (v: number) => void; min?: number; max?: number; step?: number }) {
  return (
    <div className="flex items-center gap-3">
      <input type="range" min={min} max={max} step={step} value={value} onChange={(e) => onChange(Number(e.target.value))} className="flex-1" />
      <span className="num w-12 text-right font-mono text-[12px] text-ink">{value.toFixed(2)}</span>
    </div>
  );
}

function Select({ value, options, onChange }: { value: string; options: string[]; onChange: (v: string) => void }) {
  return (
    <select className={cx(inputCls, "py-1.5")} value={value} onChange={(e) => onChange(e.target.value)}>
      {options.map((o) => <option key={o} value={o}>{o}</option>)}
    </select>
  );
}

function Section({ id, title, description, value, onSaved, render }: {
  id: string; title: string; description: string; value: any; onSaved: () => void;
  render: (draft: any, set: (path: (string | number)[], v: any) => void) => ReactNode;
}) {
  const [draft, setDraft] = useState<any>(() => clone(value));
  const [json, setJson] = useState(false);
  const [jsonText, setJsonText] = useState("");
  const [busy, setBusy] = useState(false);
  const [error, setError] = useState<ApiError | Error | null>(null);
  const [saved, setSaved] = useState(false);
  const original = useMemo(() => JSON.stringify(value), [value]);
  useEffect(() => { setDraft(clone(value)); setJsonText(JSON.stringify(value, null, 2)); }, [original]); // eslint-disable-line react-hooks/exhaustive-deps
  const dirty = (json ? jsonText !== JSON.stringify(value, null, 2) : JSON.stringify(draft) !== original);

  const set = (path: (string | number)[], v: any) => {
    setDraft((d: any) => {
      const next = clone(d);
      let cur = next;
      for (let i = 0; i < path.length - 1; i++) cur = cur[path[i]];
      cur[path[path.length - 1]] = v;
      return next;
    });
    setSaved(false);
  };

  async function save() {
    setBusy(true);
    setError(null);
    try {
      const body = json ? JSON.parse(jsonText) : draft;
      await api.put(`/api/v1/policies/${id}`, { value: body, comment: `updated ${id} from console` });
      setSaved(true);
      onSaved();
    } catch (e) {
      setError(e instanceof SyntaxError ? new Error("Invalid JSON: " + e.message) : (e as ApiError));
    } finally {
      setBusy(false);
    }
  }

  return (
    <Card title={title} actions={
      <>
        {saved && <span className="text-[12px] text-allow">saved</span>}
        <button className={btnGhost} onClick={() => {
          if (json) {
            try { setDraft(JSON.parse(jsonText)); setError(null); } catch (e) { setError(new Error("Invalid JSON: " + (e as Error).message)); return; }
          } else {
            setJsonText(JSON.stringify(draft, null, 2));
          }
          setJson(!json);
        }}>
          <Braces className="h-3.5 w-3.5" /> {json ? "Form" : "JSON"}
        </button>
        <button className={btnGhost} disabled={!dirty || busy} onClick={() => { setDraft(clone(value)); setJsonText(JSON.stringify(value, null, 2)); setError(null); }}>
          <RotateCcw className="h-3.5 w-3.5" />
        </button>
        <button className={btnPrimary + " py-1.5"} disabled={!dirty || busy} onClick={save}><Save className="h-3.5 w-3.5" /> Save</button>
      </>
    }>
      <p className="mb-3 text-[12px] text-ink-3">{description}</p>
      {json ? (
        <textarea className={cx(inputCls, "h-72 font-mono text-[12px]")} value={jsonText} onChange={(e) => setJsonText(e.target.value)} spellCheck={false} />
      ) : render(draft, set)}
      {error && <div className="mt-3"><ErrorNote error={error} /></div>}
    </Card>
  );
}

function DetectorForm({ d, set, criticalActions }: { d: any; set: (p: (string | number)[], v: any) => void; criticalActions: string[] }) {
  return (
    <div className="grid gap-4 md:grid-cols-2">
      <div className="space-y-3">
        <Toggle checked={d.enabled} onChange={(v) => set(["enabled"], v)} label="Detector enabled" />
        <Field label="Threshold" hint="score at or above this triggers the action"><Slider value={d.threshold} onChange={(v) => set(["threshold"], v)} min={0.05} /></Field>
        <Field label="ML trust weight" hint="when no rule corroborates the classifier"><Slider value={d.ml_weight} onChange={(v) => set(["ml_weight"], v)} /></Field>
        {d.verify_band && (
          <Field label="Verification band start" hint="scores in [start, threshold) are verified (escalate-only)">
            <Slider value={d.verify_band[0]} onChange={(v) => set(["verify_band"], [Math.min(v, d.threshold - 0.01), d.threshold])} />
          </Field>
        )}
      </div>
      <div className="grid content-start gap-3 sm:grid-cols-2">
        <Field label="Action"><Select value={d.action} options={criticalActions} onChange={(v) => set(["action"], v)} /></Field>
        <Field label="On detector error"><Select value={d.on_error} options={["BLOCK", "HUMAN_REVIEW"]} onChange={(v) => set(["on_error"], v)} /></Field>
        <Field label="Detection mode"><Select value={d.mode} options={["hybrid", "rules", "ml"]} onChange={(v) => set(["mode"], v)} /></Field>
      </div>
    </div>
  );
}

export default function Policies() {
  const { data, error, reload } = useApi<PolicyResponse>("/api/v1/policies");
  if (!data) return error ? <ErrorNote error={error} /> : <Spinner />;
  const p = data.policy;
  const providerOptions = Array.from(new Set([...data.providers_configured, ...p.providers.allowed_providers]));

  return (
    <div className="space-y-5">
      <div className="flex flex-wrap items-end justify-between gap-3">
        <div>
          <h1 className="text-xl font-semibold tracking-tight">Policy configuration</h1>
          <p className="text-sm text-ink-3">Changes are validated server-side, versioned, audited and take effect on the next request. Safety invariants cannot be configured away.</p>
        </div>
        <div className="rounded-lg border border-line bg-panel px-3 py-2 text-[12px] text-ink-3">
          version <b className="num text-ink">v{data.version}</b> · hash <Mono className="text-ink-2">{data.hash.slice(0, 12)}</Mono>
        </div>
      </div>

      <div className="grid gap-4 xl:grid-cols-[minmax(0,1fr)_300px]">
        <div className="min-w-0 space-y-4">
          <Section id="prompt_injection" title="Prompt injection" value={p.prompt_injection} onSaved={reload}
            description="Hybrid rules + DeBERTa classifier. VERIFY is not allowed as the action: the LLM verifier can only escalate."
            render={(d, set) => <DetectorForm d={d} set={set} criticalActions={["BLOCK", "HUMAN_REVIEW", "ALLOW"]} />} />
          <Section id="jailbreak" title="Jailbreak" value={p.jailbreak} onSaved={reload}
            description="Persona, DAN, safety-bypass and multi-turn manipulation detection."
            render={(d, set) => <DetectorForm d={d} set={set} criticalActions={["BLOCK", "HUMAN_REVIEW", "ALLOW"]} />} />
          <Section id="pii" title="Sensitive data (PII)" value={p.pii} onSaved={reload}
            description="Presidio entity detection. Cloud providers always receive redacted text when the provider policy requires it."
            render={(d, set) => (
              <div className="grid gap-4 md:grid-cols-2">
                <div className="space-y-3">
                  <Toggle checked={d.enabled} onChange={(v) => set(["enabled"], v)} label="PII detection enabled" />
                  <Toggle checked={d.allow_restoration} onChange={(v) => set(["allow_restoration"], v)} label="Allow placeholder restoration (to the original caller only)" />
                  <Field label="Entity score threshold"><Slider value={d.score_threshold} onChange={(v) => set(["score_threshold"], v)} /></Field>
                </div>
                <div className="space-y-3">
                  <Field label="Action"><Select value={d.action} options={["REDACT", "ALLOW", "HUMAN_REVIEW", "BLOCK"]} onChange={(v) => set(["action"], v)} /></Field>
                  <Field label="Block these entity types" hint="comma separated">
                    <input className={inputCls} value={d.block_entities.join(", ")} onChange={(e) => set(["block_entities"], e.target.value.split(",").map((s) => s.trim()).filter(Boolean))} placeholder="e.g. US_SSN, IN_AADHAAR" />
                  </Field>
                  <div className="text-[12px] text-ink-3">Custom entities: {d.custom_entities.map((c: any) => <Mono key={c.name} className="mr-1.5 text-ink-2">{c.name}</Mono>)} (edit in JSON)</div>
                </div>
              </div>
            )} />
          <Section id="secret_detection" title="Secrets and credentials" value={p.secret_detection} onSaved={reload}
            description="Deterministic: API keys, tokens, private keys, connection strings, password assignments, high-entropy strings. Only BLOCK or REDACT are permitted."
            render={(d, set) => (
              <div className="grid gap-4 md:grid-cols-3">
                <Toggle checked={d.enabled} onChange={(v) => set(["enabled"], v)} label="Enabled" />
                <Toggle checked={d.entropy} onChange={(v) => set(["entropy"], v)} label="Entropy heuristics" />
                <Field label="Action"><Select value={d.action} options={["BLOCK", "REDACT"]} onChange={(v) => set(["action"], v)} /></Field>
              </div>
            )} />
          <Section id="toxicity" title="Toxicity" value={p.toxicity} onSaved={reload}
            description="Separate category from injection. VERIFY sends the text to the local verifier before deciding."
            render={(d, set) => (
              <div className="grid gap-4 md:grid-cols-3">
                <Toggle checked={d.enabled} onChange={(v) => set(["enabled"], v)} label="Enabled" />
                <Field label="Threshold"><Slider value={d.threshold} onChange={(v) => set(["threshold"], v)} min={0.05} /></Field>
                <Field label="Action"><Select value={d.action} options={ACTIONS} onChange={(v) => set(["action"], v)} /></Field>
              </div>
            )} />
          <Section id="risk" title="Risk aggregation" value={p.risk} onSaved={reload}
            description="R = wP·P + wJ·J + wS·S + wT·T (weights normalized). Critical override keeps detected findings from being averaged away."
            render={(d, set) => (
              <div className="grid gap-4 md:grid-cols-2">
                <div className="space-y-3">
                  {Object.keys(d.weights).map((k) => (
                    <Field key={k} label={`Weight · ${k.replace("_", " ")}`}><Slider value={d.weights[k]} onChange={(v) => set(["weights", k], v)} /></Field>
                  ))}
                </div>
                <div className="space-y-3">
                  <Field label="Block threshold"><Slider value={d.block_threshold} onChange={(v) => set(["block_threshold"], v)} min={0.1} /></Field>
                  <Field label="Verify threshold"><Slider value={d.verify_threshold} onChange={(v) => set(["verify_threshold"], v)} min={0.05} /></Field>
                  <Toggle checked={d.critical_override} onChange={(v) => set(["critical_override"], v)} label="Critical override" />
                </div>
              </div>
            )} />
          <Section id="providers" title="Provider permissions" value={p.providers} onSaved={reload}
            description="Cloud fallback changes privacy properties and stays off unless enabled here AND via SENTINEL_ALLOW_CLOUD_FALLBACK."
            render={(d, set) => (
              <div className="grid gap-4 md:grid-cols-2">
                <div className="space-y-2">
                  <div className="text-[12.5px] text-ink-2">Allowed providers</div>
                  {providerOptions.map((name) => (
                    <Toggle key={name} checked={d.allowed_providers.includes(name)} label={<Mono>{name}</Mono>}
                      onChange={(v) => set(["allowed_providers"], v ? [...d.allowed_providers, name] : d.allowed_providers.filter((x: string) => x !== name))} />
                  ))}
                </div>
                <div className="space-y-3">
                  <Toggle checked={d.cloud_requires_pii_redaction} onChange={(v) => set(["cloud_requires_pii_redaction"], v)} label="Redact PII before cloud transmission" />
                  <Toggle checked={d.cloud_block_secrets} onChange={(v) => set(["cloud_block_secrets"], v)} label="Always block secrets for cloud" />
                  <Toggle checked={d.allow_cloud_fallback} onChange={(v) => set(["allow_cloud_fallback"], v)} label="Allow local → cloud fallback" />
                  <Field label="Max output tokens"><input type="number" className={inputCls} value={d.max_output_tokens} onChange={(e) => set(["max_output_tokens"], Number(e.target.value))} /></Field>
                </div>
              </div>
            )} />
          <Section id="tools" title="Tool permissions" value={p.tools} onSaved={reload}
            description="Default-deny allowlist. Write tools need write permission, an allowed scope and (if configured) an admin-issued approval token bound to the exact arguments."
            render={(d, set) => (
              <div className="overflow-x-auto">
                <Toggle checked={d.enabled} onChange={(v) => set(["enabled"], v)} label="Tool execution enabled" />
                <table className="mt-3 w-full text-left text-[12.5px]">
                  <thead className="text-[11px] text-ink-3 uppercase"><tr className="border-b border-line">
                    <th className="py-2 pr-2 font-medium">Tool</th><th className="px-2 font-medium">Enabled</th><th className="px-2 font-medium">Permission</th>
                    <th className="px-2 font-medium">Approval</th><th className="px-2 font-medium">Scopes</th><th className="px-2 font-medium">Max calls</th></tr></thead>
                  <tbody>
                    {Object.entries(d.tools).map(([name, t]: [string, any]) => (
                      <tr key={name} className="border-b border-line/60">
                        <td className="py-2 pr-2"><Mono className="text-ink">{name}</Mono><div className="text-[11px] text-ink-3">{t.description}</div></td>
                        <td className="px-2"><Toggle checked={t.enabled} onChange={(v) => set(["tools", name, "enabled"], v)} /></td>
                        <td className="px-2"><span className={t.permission === "write" ? "text-redact" : "text-ink-2"}>{t.permission}</span></td>
                        <td className="px-2"><Toggle checked={t.requires_approval} onChange={(v) => set(["tools", name, "requires_approval"], v)} /></td>
                        <td className="px-2 font-mono text-[11px] text-ink-3">{t.allowed_scopes.join(", ")}</td>
                        <td className="px-2"><input type="number" min={0} className={cx(inputCls, "w-20 py-1")} value={t.max_calls_per_session}
                          onChange={(e) => set(["tools", name, "max_calls_per_session"], Number(e.target.value))} /></td>
                      </tr>
                    ))}
                  </tbody>
                </table>
              </div>
            )} />
          {(["verification", "output", "context", "context_profiles"] as const).map((id) => (
            <Section key={id} id={id} title={id.replace("_", " ")} value={p[id]} onSaved={reload}
              description={{
                verification: "Escalate-only secondary LLM verification for uncertain scores.",
                output: "Output validation actions (ALLOW / REDACT / BLOCK only).",
                context: "Untrusted retrieved-content scanning (DROP, SANITIZE or FLAG chunks).",
                context_profiles: "Application context profiles (bounded threshold multipliers, weight overrides).",
              }[id]}
              render={(d) => <pre className="max-h-56 overflow-auto rounded-lg border border-line bg-canvas p-3 font-mono text-[11.5px] text-ink-2">{JSON.stringify(d, null, 2)}</pre>} />
          ))}
        </div>

        <div className="space-y-4">
          <Card title={<span className="flex items-center gap-1.5"><History className="h-3.5 w-3.5" /> Recent changes</span>}>
            {data.recent_changes.length === 0 ? <div className="text-sm text-ink-3">No changes since startup (file policy).</div> : (
              <ul className="space-y-2.5 text-[12.5px]">
                {data.recent_changes.map((c, i) => (
                  <li key={i} className="border-l-2 border-accent/40 pl-2.5">
                    <div><Mono className="text-ink">{c.section}</Mono> <span className="text-ink-3">v{c.from_version} → v{c.to_version}</span></div>
                    <div className="text-[11px] text-ink-3">{fmtTime(c.timestamp)} · {c.actor}</div>
                  </li>
                ))}
              </ul>
            )}
          </Card>
          <Card title="Enforced invariants">
            <ul className="list-disc space-y-1.5 pl-4 text-[12px] text-ink-3">
              <li>Secrets are only ever BLOCKed or REDACTed.</li>
              <li>Injection, jailbreak, PII and secret checks fail closed on error.</li>
              <li>The LLM verifier can escalate, never authorize.</li>
              <li>Profile multipliers stay within [0.8, 1.5].</li>
              <li>Tools are default-deny; VERIFY is not a tool decision.</li>
              <li>Retrieved content has no write path to policy or tools.</li>
            </ul>
          </Card>
        </div>
      </div>
    </div>
  );
}
