/**
 * Backend session discovery.
 *
 * Production: the Tauri shell starts the backend with a random per-launch token and hands
 * {baseUrl, token} to the webview over IPC. The token lives only in memory.
 * Development: Vite env vars supplied by scripts/dev.sh (a throwaway per-run token).
 */
export interface Session {
  baseUrl: string;
  token: string;
  source: "tauri" | "dev";
}

declare global {
  interface Window {
    __TAURI_INTERNALS__?: unknown;
  }
}

export async function discoverSession(): Promise<Session | null> {
  if (typeof window !== "undefined" && window.__TAURI_INTERNALS__) {
    const { invoke } = await import("@tauri-apps/api/core");
    const s = await invoke<{ base_url: string; token: string }>("get_session");
    return { baseUrl: s.base_url, token: s.token, source: "tauri" };
  }
  if (import.meta.env.DEV) {
    const baseUrl = import.meta.env.VITE_JARVIS_API as string | undefined;
    const token = import.meta.env.VITE_JARVIS_DEV_TOKEN as string | undefined;
    if (baseUrl && token) return { baseUrl, token, source: "dev" };
  }
  return null;
}
