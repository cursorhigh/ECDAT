export type JsonRecord = Record<string, unknown>;

export interface Envelope<T> {
  success: boolean;
  code: string;
  message: string;
  data: T;
  meta?: {
    request_id?: string;
    timestamp?: string;
  };
  errors?: Array<{ field?: string; message?: string }>;
}

export interface Page<T> {
  count: number;
  next: string | null;
  previous: string | null;
  results: T[];
}

export interface WorkerState {
  /** "inline" when HUEY_IMMEDIATE runs tasks in-process; otherwise "queue". */
  mode: "inline" | "queue" | "unknown" | string;
  /** True only while a worker heartbeat is fresh. */
  running: boolean;
  state: "online" | "idle" | "stale" | "not_running" | "inline" | "unknown" | string;
  pending: number;
  scheduled: number;
  workers: number | null;
  last_seen: number | null;
  age_seconds: number | null;
  detail: string;
}

export interface Health {
  service: string;
  status: "ok" | "degraded" | string;
  time: string;
  active_db: string;
  database_up: boolean;
  /** Measured worker/queue state. Absent on older backends. */
  worker?: WorkerState;
}

export interface SessionInfo {
  session_id: number | null;
  session_name: string | null;
  scope: "all" | "session";
  counts: {
    scans: number;
    raw_findings: number;
    normalized: number;
    assets: number;
    relations: number;
    analysis_runs: number;
    assessments: number;
    audit: number;
  };
}

export interface RecentSession {
  id: number;
  name: string;
}

export interface ScanJob {
  id: number;
  source_type: string;
  source_type_display?: string;
  target: string;
  status: string;
  status_display?: string;
  progress: number;
  progress_stage?: string;
  items_total?: number | null;
  items_scanned?: number;
  items_skipped?: number;
  /** Per-reason breakdown of what could not be inspected. */
  skip_reasons?: Record<string, number>;
  skip_reason_labels?: Array<{
    reason: string;
    count: number;
    label: string;
  }>;
  findings_count: number;
  /** Set when this job is one source of a multi-source run. */
  batch?: number | null;
  error?: string | null;
  error_code?: string;
  error_scope?: string;
  error_recoverable?: boolean | null;
  error_action?: string;
  started_at?: string | null;
  finished_at?: string | null;
  created_at: string;
  session?: { id: number; name: string };
}

export interface BrowseResult {
  path: string;
  parent: string | null;
  folders: string[];
  error?: string;
}

export interface ScanPreview {
  platform: string;
  scan_type: string;
  roots: Array<{ root: string; label: string; scan_all: boolean }>;
}

export interface DependencyNode {
  id: string;
  package: string;
  version: string;
  ecosystem: string;
  scope: string;
  is_crypto: boolean;
  relevance: string;
  capability: string;
  key_service: string;
}

export interface DependencyEdge {
  from: string;
  to: string;
  kind: "depends_on" | "provides" | string;
  detail: string;
}

export interface DependencyRecord {
  id: number;
  package: string;
  version: string;
  ecosystem: string;
  scope: "runtime" | "development" | string;
  is_crypto: boolean;
  relevance: string;
  capability: string;
  key_service: string;
  family: string;
  location: string;
  evidence?: Record<string, unknown> | null;
}

export interface ScannerDescriptor {
  id: string;
  source_type: string;
  name: string;
  description: string;
  version: string;
  supported_targets: string[];
  supported_artifacts: string[];
  capabilities: string[];
  configuration_schema: Record<string, { type: string; label: string; default: number | string; min?: number }>;
  status: "available" | "planned";
}

export interface ScannerScopeInfo {
  roots: Array<{ root: string; label: string }>;
  unbounded: boolean;
}

export interface ScannerRegistry {
  scanners: ScannerDescriptor[];
  available: string[];
  platform?: string;
  /** What each non-target scope will actually read on this machine. */
  scopes?: Record<"quick" | "whole", ScannerScopeInfo>;
}

export interface NormalizedFinding {
  id: number;
  raw_finding: number;
  kind: string;
  kind_display?: string;
  family: string;
  family_display?: string;
  algorithm?: string | null;
  key_size?: number | null;
  curve?: string | null;
  protocol?: string | null;
  library?: string | null;
  library_version?: string | null;
  confidence?: number | null;
  line?: number | null;
  evidence?: Record<string, unknown> | null;
}

export interface Asset {
  id: number;
  name: string;
  asset_type?: string;
  asset_type_display?: string;
  identifier?: string;
  environment?: string;
  occurrence_count?: number;
  family: string;
  family_display?: string;
  algorithm?: string | null;
  key_size?: number | null;
  curve?: string | null;
  protocol?: string | null;
  library?: string | null;
  library_version?: string | null;
  source_type?: string | null;
  location?: string | null;
  owner?: string | null;
  inventory_status?: string | null;
  inventory_status_display?: string | null;
  created_at?: string;
}

export interface AssetOccurrence {
  id: number;
  asset: number;
  asset_name: string;
  asset_type: string;
  scan_job: number | null;
  finding: number | null;
  location: string;
  line: number | null;
  first_seen: string;
  last_seen: string;
  evidence?: Record<string, unknown> | null;
}

export interface ReportingOverview {
  kpis: {
    // Asset-based (deduplicated inventory).
    assets: number;
    quantum_vuln: number;
    quantum_vuln_pct: number;
    weak: number;
    pqc_ready: number;
    pqc_ready_pct: number;
    /** Scan jobs in scope, i.e. one per source. NOT a count of runs. */
    scans: number;
    analysed: number;
    mitigation_assets: number;
    plan_count: number;
    /** Distinct source types actually scanned in this session. */
    sources_scanned: number;
    findings: number;
    // Finding-based (one assessment per finding, so these are larger than
    // `assets` and must not be presented as the same unit).
    needs_migration: number;
    needs_migration_pct: number;
    /** Distinct assets behind those findings. This is the actionable count. */
    needs_migration_assets: number;
    hndl_exposed: number;
    hndl_exposed_pct: number;
    hndl_exposed_assets: number;
    assessed: number;
    not_assessable: number;
    not_assessable_pct: number;
    // Scan coverage: only sources that report a total contribute a denominator.
    coverage_pct: number;
    items_total: number;
    items_scanned: number;
  };

  analysis_done: boolean;
  analysis_assets: number;
  mitigation_done: boolean;
  scan_running: number;
  analysis_running: number;
  workflow: Array<{
    name: string;
    key: string;
    count: number;
    detail: string;
    done: boolean;
    api: string;
    sub: Array<{ label: string; count: number }>;
  }>;
  asset_by_family: Array<{ family?: string | null; count: number }>;
  risk_split: Array<{ key: string; label: string; count: number }>;
  vuln_priorities: Array<{
    asset: Asset;
    score: number;
    risk_label: string;
    risk_badge: string;
    replacement: string;
  }>;
  recent_scans: Array<Pick<ScanJob, "id" | "target" | "source_type" | "status" | "created_at">>;
}

export interface Stats {
  scan_total?: number;
  scan_completed?: number;
  scan_running?: number;
  scan_failed?: number;
  raw_total?: number;
  normalized_total?: number;
  asset_total?: number;
  scan_partial?: number;
  scan_cancelled?: number;
  relation_total?: number;
  dependency_total?: number;
  dependency_edge_total?: number;
  audit_total?: number;
  asset_by_family?: Array<{ family?: string | null; count: number }>;
  asset_by_source?: Array<{ source_type?: string | null; count: number }>;
  asset_by_owner?: Array<{ owner?: string | null; count: number }>;
  asset_by_status?: Array<{ inventory_status?: string | null; count: number }>;
  raw_by_source?: Array<{ source_type?: string | null; count: number }>;
  raw_by_status?: Array<{ status?: string | null; count: number }>;
  normalized_unknown?: number;
  [key: string]: unknown;
}

export interface AnalysisListItem {
  id: number;
  scan_job_id: number;
  target: string;
  status: string;
  progress: number;
  created_at: string;
  assets: number;
  /**
   * Seconds left before a parked (AWAITING_CONTEXT) run falls back to the
   * conservative defaults. 0 when the run was dispatched immediately. Taken
   * from the server so the countdown matches the real deadline.
   */
  context_deadline_seconds?: number;
}

export interface Assessment {
  id: number;
  finding_ref?: string | null;
  asset_id?: number | string | null;
  asset_name?: string;
  asset_family?: string;
  cbom_asset?: JsonRecord;
  hndl?: JsonRecord;
  mosca?: JsonRecord;
}

export interface AnalysisDetail {
  id: number;
  scan_job_id: number;
  target: string;
  mode?: string;
  status: string;
  progress: number;
  error?: string | null;
  created_at: string;
  started_at?: string | null;
  finished_at?: string | null;
  repository?: string | null;
  raw_system_context?: string | JsonRecord | null;
  risk_context?: JsonRecord;
  executive_summary?: JsonRecord;
  summary_rows: Array<{
    asset_id?: number | string | null;
    algorithm?: string;
    algorithm_category?: string;
    classical_security?: string;
    hndl_risk?: string;
    overall_risk?: string;
    migration_priority?: string;
    quantum_vulnerable?: boolean;
  }>;
  cbom?: JsonRecord;
  findings_count?: number;
  /** Present when the analysed finding set was capped. */
  truncation?: {
    truncated: boolean;
    analysed: number;
    available: number;
    limit?: number | null;
  } | null;
  assessments?: Assessment[];
}

export interface AwaitingAnalysis {
  id: number;
  scan_job_id: number;
  target: string;
  session_id: number;
  created_at: string;
  seconds_left: number;
}

export interface MitigationPlan {
  id: number;
  run_id: number;
  scan_job_id: number;
  target: string;
  status: string;
  progress: number;
  error?: string | null;
  created_at: string;
  generated_at?: string | null;
  summary: {
    assets: number;
    urgent: number;
    quantum_vulnerable: number;
    hndl_exposed: number;
    blast_severity?: string | null;
    effort_estimate_quarters?: number | null;
  };
  document?: JsonRecord;
}

export interface MitigationOverview {
  totals: {
    plans: number;
    assets: number;
    urgent: number;
    quantum_vulnerable: number;
    hndl_exposed: number;
  };
  runs_unguarded: Array<{
    id: number;
    scan_job_id: number;
    target: string;
    assets: number;
    created_at: string;
  }>;
}

export interface AuditEntry {
  id: number;
  action: string;
  message: string;
  target_type?: string | null;
  target_id?: string | number | null;
  actor?: string | null;
  session_id?: number | null;
  /** Session name snapshotted at write time; still set after the session is gone. */
  session_name?: string | null;
  /** True when the owning session was deleted and the entry no longer matches a session filter. */
  orphaned?: boolean;
  created_at: string;
}

export interface AuditResponse {
  count: number;
  entries: AuditEntry[];
}

export interface ReportPayload {
  b64: string;
  filename: string;
  mime: string;
  format: string;
  size?: number;
  generated_at?: string;
  render_error?: string | null;
  scope?: string;
}

export interface StartScanPayload {
  scan_type: "quick" | "whole" | "specified";
  /** Resolved from the scanner registry; not a fixed union. */
  source_type: string;
  /** Run several sources in one action. Takes precedence over source_type. */
  source_types?: string[];
  target: string;
  options: Record<string, number>;
}

/** One source within a multi-source run. */
export interface ScanBatchSource {
  id: number;
  source_type: string;
  status: string;
  progress: number;
  items_total?: number | null;
  items_scanned?: number;
  items_skipped?: number;
  findings_count?: number;
  error?: string | null;
  error_code?: string;
  error_action?: string;
  skip_reasons?: Record<string, number>;
  skip_reason_labels?: Array<{ reason: string; count: number; label: string }>;
}

/**
 * A single user-initiated discovery run across several sources.
 *
 * Returned by start-scan when more than one source is requested. Status and
 * progress are derived from `sources`, so this can never claim more coverage
 * than the individual sources achieved.
 */
export interface ScanBatch {
  id: number;
  target: string;
  scan_type: string;
  source_types: string[];
  excluded: Array<{ source: string; reason: string }>;
  sources: ScanBatchSource[];
  status: string;
  status_display?: string;
  progress: number;
  findings_count?: number;
  created_at?: string;
  finished_at?: string | null;
  session?: { id: number; name: string };
}

/** One typed node in the unified relationship graph. */
export interface GraphNodeRow {
  id: number;
  node_type: string;
  node_type_display: string;
  key: string;
  label: string;
  family: string;
  algorithm: string;
  asset_type: string;
  source_type: string;
  location: string;
  detail: JsonRecord;
}

export interface GraphEdgeRow {
  from: number;
  to: number;
  kind: string;
  why: JsonRecord;
}

export interface GraphIndex {
  stats: {
    nodes: number;
    edges: number;
    nodes_by_type: Record<string, number>;
    edges_by_type: Record<string, number>;
  };
  nodes: GraphNodeRow[];
  edges: GraphEdgeRow[];
}

/** One hop in an impact path. Present on the first hop too. */
export interface GraphHop {
  node: GraphNodeRow;
  relation: string | null;
  why: JsonRecord;
}

export interface GraphPath {
  path: GraphHop[];
  length: number;
}

export interface GraphImpact {
  question: string;
  node: GraphNodeRow | null;
  paths: GraphPath[];
  count: number;
  truncated?: boolean;
  by_type?: Record<string, number>;
  affected?: GraphNodeRow[];
}

/** One recorded scan inside a session, as the audit history reports it. */
export interface ScanHistoryJob {
  id: number;
  session_id: number;
  source_type: string;
  target: string;
  status: string;
  findings_count: number;
  items_scanned: number;
  items_skipped: number;
  created_at: string;
}

/**
 * A session is one scan, so this is the cross-session history that replaced the
 * "all data" scope. Audit is the only place allowed to span sessions.
 */
export interface ScanHistorySession {
  id: number;
  name: string;
  created_at: string;
  is_active: boolean;
  scans: ScanHistoryJob[];
}

export interface ScanHistory {
  count: number;
  active_session_id: number | null;
  sessions: ScanHistorySession[];
}
/** How much of the scope discovery actually read. */
export interface HandoffCoverage {
  scan_status: string;
  items_total: number | null;
  items_scanned: number;
  items_skipped: number;
  skip_reasons: Record<string, number>;
  complete: boolean;
  sources_run: string[];
  sources_excluded: { source_type: string; label: string; reason: string }[];
  disclosure: string;
}

/** One finding as handed to the reasoning stage, with every contract answer. */
export interface HandoffFinding {
  finding_id: string;
  algorithm: string;
  family: string;
  kind: string;
  key_size: number | null;
  curve: string;
  location: string;
  source_path: string;
  line: number | null;
  source_type: string;
  detector: string;
  evidence_type: string;
  evidence: JsonRecord;
  confidence: number | null;
  validation_status: string;
  asset_id: number | null;
  asset_identifier: string;
  asset_type: string;
  asset_name: string;
  depends_on: string[];
  used_by: string[];
  /** Contract questions this finding could not answer. */
  unanswered: string[];
}

export interface HandoffQuestion {
  key: string;
  label: string;
  unanswered: number;
}

/** The Discover -> Understand dataset, with the contract made inspectable. */
export interface Handoff {
  scan_job_id: number | null;
  session_id: number | null;
  target: string;
  coverage: HandoffCoverage;
  counts: {
    findings: number;
    assets: number;
    dependencies: number;
    graph_nodes: number;
    graph_edges: number;
    findings_truncated: boolean;
  };
  contract: {
    questions: string[];
    unanswered_by_question: Record<string, number>;
    satisfied: boolean;
  };
  questions: HandoffQuestion[];
  findings: HandoffFinding[];
}
