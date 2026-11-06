import type {
  ActionRequest,
  ActionResponse,
  ApprovalOut,
  AuditEntryOut,
  AuditVerifyOut,
  CatalogOut,
  EmergencyStopReport,
  EventOut,
  HealthOut,
  JobOut,
  SystemStateOut,
  TaskOut,
} from "@jarvis/contracts";
import { API_PREFIX } from "@jarvis/contracts";
import type { Session } from "./session";

export class ApiError extends Error {
  constructor(
    public status: number,
    public code: string,
    message: string,
  ) {
    super(message);
  }
}

export class ApiClient {
  constructor(private session: Session) {}

  private async request<T>(method: string, path: string, body?: unknown): Promise<T> {
    let res: Response;
    try {
      res = await fetch(`${this.session.baseUrl}${API_PREFIX}${path}`, {
        method,
        headers: {
          Authorization: `Bearer ${this.session.token}`,
          ...(body !== undefined ? { "Content-Type": "application/json" } : {}),
        },
        body: body !== undefined ? JSON.stringify(body) : undefined,
      });
    } catch {
      throw new ApiError(0, "network_error", "Backend unreachable");
    }
    const text = await res.text();
    const data = text ? JSON.parse(text) : null;
    if (!res.ok) {
      const err = data?.error ?? {};
      throw new ApiError(res.status, err.code ?? `http_${res.status}`, err.message ?? res.statusText);
    }
    return data as T;
  }

  health = () => this.request<HealthOut>("GET", "/health");
  catalog = () => this.request<CatalogOut>("GET", "/catalog");
  systemState = () => this.request<SystemStateOut>("GET", "/system/state");
  events = (sinceSeq: number, limit = 500) =>
    this.request<EventOut[]>("GET", `/events?since_seq=${sinceSeq}&limit=${limit}`);
  submit = (req: ActionRequest) => this.request<ActionResponse>("POST", "/actions", req);
  approvals = (status?: string) =>
    this.request<ApprovalOut[]>("GET", `/approvals${status ? `?status=${status}` : ""}`);
  approve = (id: string) => this.request<ApprovalOut>("POST", `/approvals/${id}/approve`);
  deny = (id: string) => this.request<ApprovalOut>("POST", `/approvals/${id}/deny`);
  tasks = (limit = 50) => this.request<TaskOut[]>("GET", `/tasks?limit=${limit}`);
  job = (id: string) => this.request<JobOut>("GET", `/jobs/${id}`);
  cancelJob = (id: string) =>
    this.request<{ running: boolean; stopped: boolean | null; detail: string }>(
      "POST",
      `/jobs/${id}/cancel`,
    );
  emergencyStop = () => this.request<EmergencyStopReport>("POST", "/system/emergency-stop");
  audit = (limit = 100) => this.request<AuditEntryOut[]>("GET", `/audit?limit=${limit}`);
  verifyAudit = () => this.request<AuditVerifyOut>("GET", "/audit/verify");
}
