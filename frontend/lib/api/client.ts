import type {
  AnalysisDetail,
  AnalysisListItem,
  Asset,
  AuditResponse,
  BrowseResult,
  Envelope,
  Health,
  JsonRecord,
  MitigationOverview,
  MitigationPlan,
  Page,
  ReportPayload,
  ScanJob,
  ScanPreview,
  SessionInfo,
  StartScanPayload,
  Stats,
  ReportingOverview,
  AwaitingAnalysis
} from "./types";

export class ApiError extends Error {
  status: number;
  code: string;
  fieldErrors: Array<{ field?: string; message?: string }>;

  constructor(message: string, status = 500, code = "error", fieldErrors: Array<{ field?: string; message?: string }> = []) {
    super(message);
    this.name = "ApiError";
    this.status = status;
    this.code = code;
    this.fieldErrors = fieldErrors;
  }
}

type Query = Record<string, string | number | boolean | undefined | null>;

function activeSessionId() {
  if (typeof window === "undefined") return null;
  const value = window.localStorage.getItem("ecdat.active-session");
  if (!value) return null;
  const parsed = Number(value);
  return Number.isInteger(parsed) && parsed > 0 ? parsed : null;
}

function browserApiPath(path: string) {
  const normalized = path.length > 1 ? path.replace(/\/+$/, "") : path;
  return `/api/backend${normalized}`;
}

function queryString(params?: Query) {
  if (!params) return "";
  const search = new URLSearchParams();
  for (const [key, value] of Object.entries(params)) {
    if (value !== undefined && value !== null && value !== "") search.set(key, String(value));
  }
  const result = search.toString();
  return result ? `?${result}` : "";
}

async function readEnvelope<T>(response: Response): Promise<T> {
  const contentType = response.headers.get("content-type") || "";
  if (contentType.includes("application/json")) {
    const payload = (await response.json()) as Envelope<T>;
    if (!response.ok || payload.success === false) {
      throw new ApiError(
        payload.message || `Request failed with status ${response.status}`,
        response.status,
        payload.code || "request_failed",
        payload.errors || []
      );
    }
    return payload.data;
  }

  if (!response.ok) {
    const text = await response.text();
    throw new ApiError(text || `Request failed with status ${response.status}`, response.status, "request_failed");
  }
  return (await response.text()) as T;
}

async function request<T>(path: string, options: RequestInit = {}, query?: Query): Promise<T> {
  const headers = new Headers(options.headers);
  const sessionId = activeSessionId();
  if (sessionId) headers.set("X-ECDAT-Session", String(sessionId));
  const response = await fetch(`${browserApiPath(path)}${queryString(query)}`, {
    ...options,
    headers,
    cache: "no-store",
    credentials: "include"
  });
  return readEnvelope<T>(response);
}

async function requestBlob(path: string, options: RequestInit = {}, query?: Query) {
  const headers = new Headers(options.headers);
  const sessionId = activeSessionId();
  if (sessionId) headers.set("X-ECDAT-Session", String(sessionId));
  const response = await fetch(`${browserApiPath(path)}${queryString(query)}`, {
    ...options,
    headers,
    cache: "no-store",
    credentials: "include"
  });
  if (!response.ok) {
    await readEnvelope<never>(response);
  }
  return response.blob();
}

function jsonOptions(method: string, body: unknown): RequestInit {
  return {
    method,
    headers: { "Content-Type": "application/json" },
    body: JSON.stringify(body)
  };
}

export const api = {
  health: () => request<Health>("/health/"),
  sessionInfo: () => request<SessionInfo>("/session/info/"),
  createSession: (name: string) => request<{ id: number; name: string; created: boolean }>("/session/create/", jsonOptions("POST", { name })),
  switchSession: (id: number) => request<{ session_id: number; scope: string }>(`/session/switch/${id}/`, jsonOptions("POST", {})),
  resetSession: () => request<{ ok: boolean; session_id: number | null; deleted: Record<string, number> }>("/session/reset/", jsonOptions("POST", {})),
  audit: (limit = 200) => request<AuditResponse>("/session/audit/", {}, { limit }),

  scans: (query?: Query) => request<Page<ScanJob>>("/scans/", {}, query),
  scan: (id: number) => request<ScanJob>(`/scans/${id}/`),
  scanPreview: (scanType: string) => request<ScanPreview>("/scan-preview/", {}, { scan_type: scanType }),
  browse: (path?: string) => request<BrowseResult>("/browse/", {}, { path }),
  startScan: (payload: StartScanPayload) => request<ScanJob>("/start-scan/", jsonOptions("POST", payload)),
  demoScan: () => request<ScanJob>("/run-demo-scan/", jsonOptions("POST", {})),
  cancelScan: (id: number) => request<{ id: number; status: string }>(`/scans/${id}/cancel/`, jsonOptions("POST", {})),
  ingestScanData: (payload: JsonRecord) => request<ScanJob>("/scan-data/", jsonOptions("POST", payload)),

  assets: (query?: Query) => request<Page<Asset>>("/assets/", {}, query),
  asset: (id: number) => request<Asset>(`/assets/${id}/`),
  stats: () => request<Stats>("/stats/"),

  analysisList: () => request<AnalysisListItem[]>("/analysis/"),
  analysisAwaiting: () => request<AwaitingAnalysis[]>("/analysis/awaiting/"),
  analysis: (id: number) => request<AnalysisDetail>(`/analysis/${id}/`),
  startAnalysis: (payload: { scan_job: number; max_findings?: number; raw_system_context?: JsonRecord | string }) =>
    request<AnalysisListItem>("/analysis/start/", jsonOptions("POST", payload)),
  cancelAnalysis: (id: number) => request<{ id: number; status: string }>(`/analysis/${id}/cancel/`, jsonOptions("POST", {})),
  analysisArtifacts: (id: number) => request<JsonRecord>(`/analysis/${id}/artifacts/`),

  mitigationList: () => request<MitigationPlan[]>("/mitigation/"),
  mitigationOverview: () => request<MitigationOverview>("/mitigation/overview/"),
  mitigation: (id: number) => request<MitigationPlan>(`/mitigation/${id}/`),
  generateMitigation: (runId: number) => request<MitigationPlan>(`/mitigation/run/${runId}/generate/`, jsonOptions("POST", { run: runId })),
  cancelMitigation: (id: number) => request<{ id: number; status: string }>(`/mitigation/${id}/cancel/`, jsonOptions("POST", {})),

  reportingOverview: () => request<ReportingOverview>("/reporting/overview/"),
  reportingPipeline: () => request<{ stages: Array<{ name: string; key: string; count: number; detail: string; done: boolean; sub: Array<{ label: string; count: number }> }> }>("/reporting/pipeline/"),
  reportsBlob: (path: string) => requestBlob(path),
  fullReport: () => request<ReportPayload>("/reports/full.json", jsonOptions("POST", {}))
};
