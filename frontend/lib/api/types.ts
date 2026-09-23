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

export interface Health {
  service: string;
  status: "ok" | "degraded" | string;
  time: string;
  active_mode: string;
  active_db: string;
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
  findings_count: number;
  error?: string | null;
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

export interface Asset {
  id: number;
  name: string;
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

export interface ReportingOverview {
  kpis: {
    assets: number;
    quantum_vuln: number;
    quantum_vuln_pct: number;
    weak: number;
    pqc_ready: number;
    pqc_ready_pct: number;
    scans: number;
    analysed: number;
    mitigation_assets: number;
    plan_count: number;
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
  relation_total?: number;
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
  source_type: "source_code";
  target: string;
  options: {
    max_files?: number;
    max_depth?: number;
    max_file_size?: number;
  };
}
