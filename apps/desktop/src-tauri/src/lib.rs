//! JARVIS desktop shell.
//!
//! Responsibilities (and nothing more):
//! 1. Generate a random per-launch session token (never written to disk).
//! 2. Pick a free loopback port and start the Python backend bound to 127.0.0.1.
//! 3. Hand {base_url, token} to the webview via the `get_session` IPC command.
//! 4. Terminate the backend when the app exits.
//!
//! The webview gets no shell, filesystem or process plugins. All privileged work goes through
//! the backend, where the policy engine enforces permission levels.

use std::net::TcpListener;
use std::path::PathBuf;
use std::process::{Child, Command, Stdio};
use std::sync::Mutex;

use base64::Engine;
use serde::Serialize;
use tauri::{Manager, RunEvent, State};

#[derive(Clone, Serialize)]
struct SessionInfo {
    base_url: String,
    token: String,
}

struct Backend {
    session: SessionInfo,
    child: Mutex<Option<Child>>,
}

#[tauri::command]
fn get_session(backend: State<'_, Backend>) -> SessionInfo {
    backend.session.clone()
}

fn random_token() -> Result<String, String> {
    let mut bytes = [0u8; 32];
    getrandom::fill(&mut bytes).map_err(|e| format!("no OS randomness: {e}"))?;
    Ok(base64::engine::general_purpose::URL_SAFE_NO_PAD.encode(bytes))
}

fn free_loopback_port() -> Result<u16, String> {
    let listener = TcpListener::bind("127.0.0.1:0").map_err(|e| e.to_string())?;
    let port = listener.local_addr().map_err(|e| e.to_string())?.port();
    drop(listener);
    Ok(port)
}

/// Development: run the backend from the repository with `uv`. A packaged backend sidecar for
/// release builds is not built yet (see docs/KNOWN_ISSUES.md, KI-004).
fn backend_command(port: u16) -> Result<Command, String> {
    let dir = match std::env::var("JARVIS_BACKEND_DIR") {
        Ok(d) => PathBuf::from(d),
        Err(_) => PathBuf::from(env!("CARGO_MANIFEST_DIR")).join("../../../backend"),
    };
    let dir = dir
        .canonicalize()
        .map_err(|e| format!("backend directory not found ({}): {e}", dir.display()))?;
    let mut cmd = Command::new("uv");
    cmd.args(["run", "jarvis-backend", "--port", &port.to_string()])
        .current_dir(dir)
        .stdin(Stdio::null());
    #[cfg(windows)]
    {
        use std::os::windows::process::CommandExt;
        const CREATE_NO_WINDOW: u32 = 0x0800_0000;
        cmd.creation_flags(CREATE_NO_WINDOW);
    }
    Ok(cmd)
}

fn start_backend() -> Result<Backend, String> {
    let token = random_token()?;
    let port = free_loopback_port()?;
    let mut cmd = backend_command(port)?;
    // The token reaches the backend through its environment only; it is never logged or stored.
    cmd.env("JARVIS_SESSION_TOKEN", &token);
    // The backend watches this PID and exits if the shell disappears (crash, or a kill that
    // only reached the `uv` launcher). See backend/jarvis/core/watchdog.py.
    cmd.env("JARVIS_PARENT_PID", std::process::id().to_string());
    let child = cmd.spawn().map_err(|e| format!("failed to start backend: {e}"))?;
    Ok(Backend {
        session: SessionInfo { base_url: format!("http://127.0.0.1:{port}"), token },
        child: Mutex::new(Some(child)),
    })
}

fn stop_backend(backend: &Backend) {
    if let Ok(mut guard) = backend.child.lock() {
        if let Some(mut child) = guard.take() {
            let _ = child.kill();
            let _ = child.wait();
        }
    }
}

#[cfg_attr(mobile, tauri::mobile_entry_point)]
pub fn run() {
    let app = tauri::Builder::default()
        .setup(|app| {
            let backend = start_backend()?;
            app.manage(backend);
            Ok(())
        })
        .invoke_handler(tauri::generate_handler![get_session])
        .build(tauri::generate_context!())
        .expect("error while building JARVIS");

    app.run(|handle, event| {
        if let RunEvent::Exit = event {
            if let Some(backend) = handle.try_state::<Backend>() {
                stop_backend(&backend);
            }
        }
    });
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn tokens_are_random_and_long() {
        let a = random_token().unwrap();
        let b = random_token().unwrap();
        assert_ne!(a, b);
        assert!(a.len() >= 43);
    }

    #[test]
    fn port_is_loopback_and_free() {
        let p = free_loopback_port().unwrap();
        assert!(p > 0);
        TcpListener::bind(("127.0.0.1", p)).expect("port should be bindable");
    }
}
