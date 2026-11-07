import { useEffect, useState, type FormEvent } from "react";
import { NavLink, Route, Routes } from "react-router-dom";
import { Activity, BarChart3, Boxes, KeyRound, LayoutDashboard, ListFilter, LogOut, ScanSearch, ShieldCheck, SlidersHorizontal } from "lucide-react";
import { getAdminKey, setAdminKey } from "./api";
import { useApi, useAuthVersion } from "./hooks";
import { btnPrimary, cx, inputCls } from "./components/ui";
import Overview from "./pages/Overview";
import Inspector from "./pages/Inspector";
import Analytics from "./pages/Analytics";
import Events from "./pages/Events";
import Policies from "./pages/Policies";
import Models from "./pages/Models";

const NAV = [
  { to: "/", label: "Overview", icon: LayoutDashboard, admin: true },
  { to: "/inspector", label: "Request Inspector", icon: ScanSearch, admin: false },
  { to: "/analytics", label: "Threat Analytics", icon: BarChart3, admin: true },
  { to: "/events", label: "Event Explorer", icon: ListFilter, admin: true },
  { to: "/policies", label: "Policies", icon: SlidersHorizontal, admin: true },
  { to: "/models", label: "Models", icon: Boxes, admin: false },
];

interface Health {
  status: string;
  version: string;
  components: { database: string; kv_store: { backend: string; status: string }; classifiers: Record<string, boolean>; pii_engine: string; policy_version: number };
}

function HealthPill() {
  const { data, error } = useApi<Health>("/api/v1/health", 15000);
  const status = error ? "offline" : data?.status ?? "…";
  const color = status === "ok" ? "var(--color-allow)" : status === "degraded" ? "var(--color-redact)" : "var(--color-block)";
  return (
    <div className="rounded-lg border border-line bg-panel-2 px-3 py-2 text-[12px]">
      <div className="flex items-center gap-2">
        <span className="relative flex h-2 w-2">
          <span className="absolute inline-flex h-full w-full animate-ping rounded-full opacity-40" style={{ background: color }} />
          <span className="relative inline-flex h-2 w-2 rounded-full" style={{ background: color }} />
        </span>
        <span className="font-medium text-ink">Gateway {status}</span>
      </div>
      {data && (
        <div className="mt-1.5 space-y-0.5 text-ink-3">
          <div>policy v{data.components.policy_version} · {data.components.pii_engine}</div>
          <div>store: {data.components.kv_store.backend}</div>
        </div>
      )}
    </div>
  );
}

function AdminGate({ onDone }: { onDone?: () => void }) {
  const [key, setKey] = useState("");
  const submit = (e: FormEvent) => {
    e.preventDefault();
    if (key.trim()) {
      setAdminKey(key.trim());
      onDone?.();
    }
  };
  return (
    <div className="mx-auto mt-16 max-w-md rounded-xl border border-line bg-panel p-6">
      <div className="flex items-center gap-2 text-ink">
        <KeyRound className="h-5 w-5 text-accent" />
        <h2 className="text-lg font-semibold">Administrator access</h2>
      </div>
      <p className="mt-2 text-sm text-ink-3">
        This view needs the gateway admin key (<span className="font-mono">SENTINEL_ADMIN_API_KEY</span>). It is kept in session
        storage for this tab only and sent as <span className="font-mono">X-API-Key</span>.
      </p>
      <form onSubmit={submit} className="mt-4 space-y-3">
        <input type="password" autoComplete="off" className={inputCls} placeholder="Admin API key" value={key} onChange={(e) => setKey(e.target.value)} />
        <button className={btnPrimary} type="submit" disabled={!key.trim()}>Unlock console</button>
      </form>
    </div>
  );
}

function Protected({ children }: { children: React.ReactNode }) {
  useAuthVersion();
  const [denied, setDenied] = useState(false);
  useEffect(() => {
    const h = () => setDenied(true);
    window.addEventListener("sentinel-unauthorized", h);
    return () => window.removeEventListener("sentinel-unauthorized", h);
  }, []);
  if (!getAdminKey() || denied) {
    return (
      <>
        {denied && getAdminKey() && <p className="mx-auto mt-8 max-w-md text-center text-sm text-block">The stored key was rejected.</p>}
        <AdminGate onDone={() => setDenied(false)} />
      </>
    );
  }
  return <>{children}</>;
}

export default function App() {
  useAuthVersion();
  const hasKey = !!getAdminKey();
  return (
    <div className="flex h-full">
      <aside className="flex w-60 shrink-0 flex-col border-r border-line bg-panel">
        <div className="flex items-center gap-2.5 px-5 py-5">
          <ShieldCheck className="h-6 w-6 text-accent" />
          <div>
            <div className="text-[15px] font-semibold tracking-tight">SentinelLLM</div>
            <div className="text-[11px] text-ink-3">LLM firewall console</div>
          </div>
        </div>
        <nav className="flex-1 space-y-0.5 px-3">
          {NAV.map(({ to, label, icon: Icon }) => (
            <NavLink
              key={to}
              to={to}
              end={to === "/"}
              className={({ isActive }) =>
                cx("flex items-center gap-2.5 rounded-lg px-3 py-2 text-[13.5px] transition-colors",
                  isActive ? "bg-accent/10 text-ink ring-1 ring-accent/30" : "text-ink-2 hover:bg-panel-2 hover:text-ink")
              }
            >
              <Icon className="h-4 w-4" />
              {label}
            </NavLink>
          ))}
        </nav>
        <div className="space-y-2 p-3">
          <HealthPill />
          {hasKey ? (
            <button onClick={() => setAdminKey(null)} className="flex w-full items-center gap-2 rounded-lg px-3 py-2 text-[12.5px] text-ink-3 hover:bg-panel-2 hover:text-ink">
              <LogOut className="h-3.5 w-3.5" /> Lock console
            </button>
          ) : (
            <div className="flex items-center gap-2 px-3 py-1 text-[12px] text-ink-3"><Activity className="h-3.5 w-3.5" /> admin locked</div>
          )}
        </div>
      </aside>
      <main className="min-w-0 flex-1 overflow-y-auto">
        <div className="mx-auto max-w-[1400px] px-6 py-6">
          <Routes>
            <Route path="/" element={<Protected><Overview /></Protected>} />
            <Route path="/inspector" element={<Inspector />} />
            <Route path="/analytics" element={<Protected><Analytics /></Protected>} />
            <Route path="/events" element={<Protected><Events /></Protected>} />
            <Route path="/policies" element={<Protected><Policies /></Protected>} />
            <Route path="/models" element={<Models />} />
          </Routes>
        </div>
      </main>
    </div>
  );
}
