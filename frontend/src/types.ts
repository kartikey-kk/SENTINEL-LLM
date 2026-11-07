export type Decision = "ALLOW" | "REDACT" | "VERIFY" | "HUMAN_REVIEW" | "BLOCK";
export type Severity = "none" | "low" | "medium" | "high" | "critical";

export interface Entity {
  type: string;
  start: number;
  end: number;
  score: number;
  recognizer: string;
  placeholder?: string | null;
}

export interface Detection {
  detector: string;
  detected: boolean;
  score: number;
  confidence: number | null;
  severity: Severity;
  reason: string;
  evidence: string[];
  method: string;
  status: string;
  latency_ms: number;
  entities: Entity[];
  metadata: Record<string, any>;
}

export interface RiskComponent {
  score: number;
  weight: number;
  contribution: number;
  sources: string[];
  status: string;
}

export interface Risk {
  score: number;
  weighted_score: number;
  severity: Severity;
  components: Record<string, RiskComponent>;
  critical_override: boolean;
  override_reasons: string[];
  incomplete: boolean;
  failed_detectors: string[];
  profile: string | null;
  explanation: string[];
}

export interface PolicyReason {
  source: string;
  action: Decision;
  rule: string;
  detail: string;
}

export interface Verification {
  status: string;
  verdict?: string | null;
  confidence?: number | null;
  provider?: string | null;
  model?: string | null;
  latency_ms?: number;
  escalate?: boolean;
}

export interface InspectInputResponse {
  request_id: string;
  decision: Decision;
  forwardable: boolean;
  risk: Risk;
  detections: Detection[];
  policy: { version: number; reasons: PolicyReason[]; initial_decision: Decision };
  sanitized_text: string;
  redactions: Entity[];
  normalization: { signals: { type: string; count: number; severity: string; detail: string }[]; removed_chars: number; decoded_views: string[] };
  verification: Verification | null;
  message: string | null;
  latency_ms: number;
}

export interface ChunkVerdict {
  id: string;
  source_type: string;
  source: string | null;
  risk: number;
  rule_score: number;
  ml_score: number | null;
  flagged: boolean;
  action: string;
  categories: string[];
  reasons: string[];
  signals: string[];
  removed_lines: number;
  redactions: Entity[];
  included: boolean;
}

export interface OutputCheck {
  check: string;
  passed: boolean;
  action: Decision;
  detail: string;
}

export interface StageSummary {
  decision: Decision;
  risk: number | null;
  detections: Detection[];
  reasons: string[];
  redactions: Entity[];
}

export interface ChatResponse {
  request_id: string;
  text: string;
  blocked: boolean;
  provider: string | null;
  model: string | null;
  security: {
    decision: Decision;
    input: StageSummary;
    context: { chunks: ChunkVerdict[]; flagged_count: number; decision: Decision } | null;
    output: StageSummary | null;
    output_checks: OutputCheck[];
    risk: Risk | null;
    verification: Verification | null;
    sanitized_prompt: string | null;
    restored_placeholders: number;
    fallback_used: boolean;
  };
  usage: { prompt_tokens: number | null; completion_tokens: number | null; llm_latency_ms: number | null };
  latency_ms: number;
}

export interface EventRow {
  request_id: string;
  timestamp: string;
  session_id: string | null;
  event_type: string;
  threat_category: string;
  threat_categories: string[];
  severity: Severity;
  risk_score: number;
  decision: Decision;
  output_decision: Decision | null;
  provider: string | null;
  model: string | null;
  processing_latency: number;
  input_preview: string | null;
  policy_version: number;
  review_status: string | null;
}

export interface EventDetail extends EventRow {
  detector_metadata: Record<string, any>;
  detections: {
    stage: string;
    detector: string;
    detected: boolean;
    score: number;
    confidence: number | null;
    severity: Severity;
    status: string;
    method: string;
    reason: string;
    latency_ms: number;
    details: Record<string, any>;
  }[];
}

export interface Metrics {
  window_hours: number;
  totals: {
    requests: number;
    threats_detected: number;
    blocked: number;
    pii_redactions: number;
    human_review: number;
    avg_latency_ms: number | null;
    p50_latency_ms: number | null;
    p95_latency_ms: number | null;
    p99_latency_ms: number | null;
  };
  decisions: Record<string, number>;
  severities: Record<string, number>;
  categories: Record<string, number>;
  event_types: Record<string, number>;
  timeseries: { bucket: string; total: number; threats: number; blocked: number; redacted: number }[];
  bucket_minutes: number;
  providers: {
    provider: string;
    model: string | null;
    requests: number;
    llm_calls: number;
    avg_llm_latency_ms: number | null;
    p95_llm_latency_ms: number | null;
    errors: number;
    prompt_tokens: number;
    completion_tokens: number;
  }[];
  detectors: { stage: string; detector: string; runs: number; detections: number; failures: number; avg_latency_ms: number | null; p95_latency_ms: number | null }[];
  reviews: { counts: Record<string, number>; observed_false_positive_rate: number | null };
  recent_events: {
    request_id: string;
    timestamp: string;
    event_type: string;
    decision: Decision;
    output_decision: Decision | null;
    threat_category: string;
    severity: Severity;
    risk_score: number;
    provider: string | null;
    latency_ms: number;
    preview: string | null;
  }[];
}
