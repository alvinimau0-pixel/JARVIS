// Generated types re-exported with friendly names. Do not hand-edit openapi.d.ts:
// run `pnpm contracts:gen` after changing backend/jarvis/api/schemas.py.
import type { components } from "./openapi";

type S = components["schemas"];

export type EventOut = S["EventOut"];
export type EventType = S["EventType"];
export type ActionRequest = S["ActionRequest"];
export type ActionResponse = S["ActionResponse"];
export type ApprovalOut = S["ApprovalOut"];
export type JobOut = S["JobOut"];
export type TaskOut = S["TaskOut"];
export type CatalogOut = S["CatalogOut"];
export type HealthOut = S["HealthOut"];
export type HealthCheck = S["HealthCheck"];
export type SystemStateOut = S["SystemStateOut"];
export type EmergencyStopReport = S["EmergencyStopReport"];
export type AuditEntryOut = S["AuditEntryOut"];
export type AuditVerifyOut = S["AuditVerifyOut"];
export type ErrorOut = S["ErrorOut"];

export const API_PREFIX = "/api/v1" as const;
export const WS_PROTOCOL = "jarvis.v1" as const;
export const WS_AUTH_PREFIX = "auth." as const;
