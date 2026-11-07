import type { ReactNode } from "react";
import { AlertTriangle, Loader2 } from "lucide-react";
import type { Decision, Severity } from "../types";
import type { ApiError } from "../api";

export const DECISION_COLOR: Record<string, string> = {
  ALLOW: "var(--color-allow)",
  REDACT: "var(--color-redact)",
  VERIFY: "var(--color-verify)",
  HUMAN_REVIEW: "var(--color-review)",
  BLOCK: "var(--color-block)",
};

export const SEVERITY_COLOR: Record<string, string> = {
  none: "#4b5567",
  low: "#60a5fa",
  medium: "#fbbf24",
  high: "#fb923c",
  critical: "#f87171",
};

export function cx(...parts: (string | false | null | undefined)[]): string {
  return parts.filter(Boolean).join(" ");
}

export function Card({ title, actions, children, className, pad = true }: {
  title?: ReactNode; actions?: ReactNode; children: ReactNode; className?: string; pad?: boolean;
}) {
  return (
    <section className={cx("rounded-xl border border-line bg-panel", className)}>
      {(title || actions) && (
        <header className="flex flex-wrap items-center justify-between gap-3 border-b border-line px-4 py-2.5">
          <h2 className="min-w-0 text-[13px] font-semibold tracking-wide text-ink-2 uppercase">{title}</h2>
          <div className="flex shrink-0 items-center gap-2">{actions}</div>
        </header>
      )}
      <div className={pad ? "p-4" : ""}>{children}</div>
    </section>
  );
}

export function Stat({ label, value, sub, tone, icon }: { label: string; value: ReactNode; sub?: ReactNode; tone?: string; icon?: ReactNode }) {
  return (
    <div className="rounded-xl border border-line bg-panel px-4 py-3.5">
      <div className="flex items-center justify-between text-[12px] font-medium text-ink-3 uppercase tracking-wide">
        <span>{label}</span>
        <span style={{ color: tone }}>{icon}</span>
      </div>
      <div className="num mt-1.5 text-[26px] leading-none font-semibold" style={{ color: tone ?? "var(--color-ink)" }}>
        {value}
      </div>
      {sub && <div className="mt-1.5 text-[12px] text-ink-3">{sub}</div>}
    </div>
  );
}

export function DecisionBadge({ decision, size = "sm" }: { decision: Decision | string | null | undefined; size?: "sm" | "lg" }) {
  if (!decision) return <span className="text-ink-3">-</span>;
  const color = DECISION_COLOR[decision] ?? "var(--color-ink-2)";
  return (
    <span
      className={cx("inline-flex items-center gap-1.5 rounded-md border font-semibold tracking-wide",
        size === "lg" ? "px-3 py-1 text-sm" : "px-1.5 py-0.5 text-[11px]")}
      style={{ color, borderColor: `color-mix(in srgb, ${color} 40%, transparent)`, background: `color-mix(in srgb, ${color} 10%, transparent)` }}
    >
      <span className="h-1.5 w-1.5 rounded-full" style={{ background: color }} />
      {decision.replace("_", " ")}
    </span>
  );
}

export function SeverityBadge({ severity }: { severity: Severity | string }) {
  const color = SEVERITY_COLOR[severity] ?? "#4b5567";
  return (
    <span className="inline-flex items-center gap-1 text-[11px] font-medium capitalize" style={{ color }}>
      <span className="h-2 w-2 rounded-sm" style={{ background: color }} />
      {severity}
    </span>
  );
}

export function ScoreBar({ value, threshold, width = 96 }: { value: number; threshold?: number; width?: number }) {
  const pct = Math.max(0, Math.min(1, value));
  const color = pct >= 0.8 ? "var(--color-block)" : pct >= 0.5 ? "var(--color-redact)" : pct >= 0.2 ? "var(--color-verify)" : "var(--color-allow)";
  return (
    <div className="flex items-center gap-2">
      <div className="relative h-1.5 rounded-full bg-line" style={{ width }}>
        <div className="absolute inset-y-0 left-0 rounded-full" style={{ width: `${pct * 100}%`, background: color }} />
        {threshold !== undefined && (
          <div className="absolute -top-1 h-3.5 w-px bg-ink-2" style={{ left: `${threshold * 100}%` }} title={`threshold ${threshold}`} />
        )}
      </div>
      <span className="num font-mono text-[12px] text-ink-2">{value.toFixed(2)}</span>
    </div>
  );
}

export function Spinner({ label }: { label?: string }) {
  return (
    <div className="flex items-center gap-2 text-sm text-ink-3">
      <Loader2 className="h-4 w-4 animate-spin" /> {label ?? "Loading"}
    </div>
  );
}

export function ErrorNote({ error }: { error: ApiError | Error | null | undefined }) {
  if (!error) return null;
  const e = error as ApiError;
  return (
    <div className="flex items-start gap-2 rounded-lg border border-block/40 bg-block/10 px-3 py-2 text-sm text-block">
      <AlertTriangle className="mt-0.5 h-4 w-4 shrink-0" />
      <div>
        <div className="font-medium">{e.message}</div>
        {e.requestId && <div className="font-mono text-[11px] opacity-80">request {e.requestId}</div>}
        {Array.isArray(e.details) && (
          <ul className="mt-1 list-disc pl-4 text-[12px] opacity-90">
            {(e.details as any[]).slice(0, 6).map((d, i) => (
              <li key={i}>{Array.isArray(d.loc) ? d.loc.join(".") + ": " : ""}{d.msg}</li>
            ))}
          </ul>
        )}
      </div>
    </div>
  );
}

export function Empty({ children }: { children: ReactNode }) {
  return <div className="py-8 text-center text-sm text-ink-3">{children}</div>;
}

export function Mono({ children, className }: { children: ReactNode; className?: string }) {
  return <span className={cx("font-mono text-[12px]", className)}>{children}</span>;
}

/** Renders text with [PLACEHOLDER_N] tokens highlighted. Pure text nodes - never HTML. */
export function RedactedText({ text }: { text: string }) {
  const parts = text.split(/(\[[A-Z][A-Z0-9_]*_\d+\])/g);
  return (
    <span className="whitespace-pre-wrap break-words">
      {parts.map((p, i) =>
        /^\[[A-Z][A-Z0-9_]*_\d+\]$/.test(p) ? (
          <span key={i} className="rounded bg-redact/15 px-1 font-mono text-[12px] text-redact">{p}</span>
        ) : (
          <span key={i}>{p}</span>
        ),
      )}
    </span>
  );
}

export function JsonBlock({ value, maxHeight = 320 }: { value: unknown; maxHeight?: number }) {
  return (
    <pre className="overflow-auto rounded-lg border border-line bg-canvas p-3 font-mono text-[11.5px] leading-relaxed text-ink-2" style={{ maxHeight }}>
      {JSON.stringify(value, null, 2)}
    </pre>
  );
}

export function Toggle({ checked, onChange, label, disabled }: { checked: boolean; onChange: (v: boolean) => void; label?: ReactNode; disabled?: boolean }) {
  return (
    <label className={cx("flex w-fit cursor-pointer items-center gap-2 text-sm", disabled && "opacity-50")}>
      <button
        type="button"
        role="switch"
        aria-checked={checked}
        disabled={disabled}
        onClick={() => onChange(!checked)}
        className={cx("relative h-5 w-9 rounded-full border transition-colors", checked ? "border-accent bg-accent/30" : "border-line-strong bg-panel-2")}
      >
        <span className={cx("absolute top-0.5 h-3.5 w-3.5 rounded-full transition-all", checked ? "left-4.5 bg-accent" : "left-0.5 bg-ink-3")} />
      </button>
      {label}
    </label>
  );
}

export const inputCls =
  "w-full rounded-lg border border-line-strong bg-canvas px-3 py-2 text-sm text-ink placeholder:text-ink-3 focus:border-accent focus:outline-none";
export const btnPrimary =
  "inline-flex items-center gap-2 rounded-lg bg-accent px-3.5 py-2 text-sm font-semibold text-canvas hover:brightness-110 disabled:cursor-not-allowed disabled:opacity-50";
export const btnGhost =
  "inline-flex items-center gap-1.5 rounded-lg border border-line-strong px-3 py-1.5 text-sm text-ink-2 hover:border-accent hover:text-ink disabled:opacity-50";

export function fmtMs(ms: number | null | undefined): string {
  if (ms === null || ms === undefined) return "-";
  if (ms >= 1000) return `${(ms / 1000).toFixed(2)} s`;
  return `${ms.toFixed(ms < 10 ? 1 : 0)} ms`;
}

export function fmtTime(iso: string): string {
  const d = new Date(iso);
  return d.toLocaleString(undefined, { month: "short", day: "2-digit", hour: "2-digit", minute: "2-digit", second: "2-digit" });
}
