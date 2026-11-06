import type { ReactNode } from "react";
import { ApiError } from "../api/client";

export function LevelBadge({ level }: { level: number | null | undefined }) {
  if (level === null || level === undefined) return null;
  const names = ["READ", "ROUTINE", "SENSITIVE", "CRITICAL"];
  return <span className={`level level-${level}`}>L{level} {names[level]}</span>;
}

export function StatusPill({ status }: { status: string }) {
  return <span className={`pill pill-${status}`}>{status.replace("_", " ")}</span>;
}

export function Empty({ title, children }: { title: string; children?: ReactNode }) {
  return (
    <div className="empty">
      <p className="empty-title">{title}</p>
      {children && <p className="empty-body">{children}</p>}
    </div>
  );
}

export function ErrorLine({ error }: { error: unknown }) {
  if (!error) return null;
  const text = error instanceof ApiError ? `${error.code}: ${error.message}` : String(error);
  return (
    <p className="error-line" role="alert">
      {text}
    </p>
  );
}

export function fmtTime(iso: string | null | undefined): string {
  if (!iso) return "—";
  return new Date(iso).toLocaleTimeString([], { hour: "2-digit", minute: "2-digit", second: "2-digit" });
}
