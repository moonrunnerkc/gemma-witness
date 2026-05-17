//! Managed inference sidecar lifecycle.
//!
//! The capture app issues a per-launch `GW_SIDECAR_TOKEN`, then either
//! attaches to an already-running sidecar on the configured loopback port or
//! spawns the kind-specific `inference/<kind>-sidecar/start.sh` script with
//! that token injected via env. The spawned child runs in foreground mode and
//! is killed via `RunEvent::ExitRequested` on app shutdown.
//!
//! Closes the manual-coordination audit note previously logged at
//! `commands/device.rs:52-54` ("the audit recommends spawning the sidecar
//! from the capture app to avoid this manual step").

use std::net::{TcpStream, ToSocketAddrs};
use std::path::PathBuf;
use std::process::{Child, Command, Stdio};
use std::sync::Mutex;
use std::time::Duration;

use rand::RngCore;
use witness_inference::SIDECAR_TOKEN_ENV;

const DEFAULT_KIND: &str = "mlx";
const DEFAULT_HOST: &str = "127.0.0.1";
const DEFAULT_PORT: u16 = 8080;

/// Wraps the spawned `start.sh` child. `shutdown` is idempotent and runs
/// from both the `RunEvent::ExitRequested` callback and the `Drop` impl, so
/// the sidecar always terminates with the app.
pub struct ManagedSidecar {
    inner: Mutex<Option<Child>>,
}

impl ManagedSidecar {
    fn new(child: Child) -> Self {
        Self {
            inner: Mutex::new(Some(child)),
        }
    }

    pub fn shutdown(&self) {
        let Ok(mut guard) = self.inner.lock() else {
            return;
        };
        let Some(mut child) = guard.take() else {
            return;
        };
        let pid = child.id();
        if let Err(err) = child.kill() {
            tracing::warn!(pid, %err, "managed sidecar kill failed");
        }
        if let Err(err) = child.wait() {
            tracing::warn!(pid, %err, "managed sidecar wait failed");
        }
        tracing::info!(pid, "managed sidecar stopped");
    }
}

impl Drop for ManagedSidecar {
    fn drop(&mut self) {
        self.shutdown();
    }
}

/// Tauri-state wrapper. `None` means the app attached to a sidecar it did
/// not spawn (operator-managed) and has nothing to tear down.
pub struct ManagedSidecarHolder(pub Option<ManagedSidecar>);

impl ManagedSidecarHolder {
    pub fn shutdown(&self) {
        if let Some(m) = &self.0 {
            m.shutdown();
        }
    }
}

fn issue_or_read_token() -> String {
    if let Ok(existing) = std::env::var(SIDECAR_TOKEN_ENV) {
        if !existing.is_empty() {
            tracing::info!("sidecar manager reusing GW_SIDECAR_TOKEN from environment");
            return existing;
        }
    }
    let mut buf = [0u8; 32];
    rand::rngs::OsRng.fill_bytes(&mut buf);
    let token = hex::encode(buf);
    std::env::set_var(SIDECAR_TOKEN_ENV, &token);
    tracing::info!("sidecar manager issued per-launch GW_SIDECAR_TOKEN");
    token
}

fn already_listening(host: &str, port: u16) -> bool {
    let addr = format!("{host}:{port}");
    let Some(socket) = addr.to_socket_addrs().ok().and_then(|mut a| a.next()) else {
        return false;
    };
    TcpStream::connect_timeout(&socket, Duration::from_millis(500)).is_ok()
}

fn resolve_script(kind: &str) -> Option<PathBuf> {
    let manifest = PathBuf::from(env!("CARGO_MANIFEST_DIR"));
    let script = manifest
        .join("../../../inference")
        .join(format!("{kind}-sidecar"))
        .join("start.sh");
    script.canonicalize().ok().filter(|p| p.is_file())
}

fn forward_lines<R>(reader: R, stream: &'static str)
where
    R: std::io::Read + Send + 'static,
{
    use std::io::{BufRead, BufReader};
    std::thread::spawn(move || {
        let buf = BufReader::new(reader);
        for line in buf.lines().map_while(Result::ok) {
            tracing::info!(target: "sidecar", stream, "{line}");
        }
    });
}

/// Probe the configured sidecar endpoint, return `None` if one is already
/// listening, otherwise spawn the kind-specific `start.sh` with the token
/// and foreground flag in env. Failure to spawn is logged and returns
/// `None` so the app still launches; the operator can run the sidecar
/// manually.
pub fn ensure_sidecar() -> Option<ManagedSidecar> {
    let kind = std::env::var("GW_SIDECAR_KIND").unwrap_or_else(|_| DEFAULT_KIND.into());
    let host = std::env::var("GW_SIDECAR_HOST").unwrap_or_else(|_| DEFAULT_HOST.into());
    let port: u16 = std::env::var("GW_SIDECAR_PORT")
        .ok()
        .and_then(|s| s.parse().ok())
        .unwrap_or(DEFAULT_PORT);

    let _ = issue_or_read_token();

    if already_listening(&host, port) {
        tracing::info!(
            %host,
            port,
            "sidecar already reachable on configured endpoint; the capture app will attach rather than spawn"
        );
        return None;
    }

    let Some(script) = resolve_script(&kind) else {
        tracing::error!(
            kind,
            "could not locate inference/{kind}-sidecar/start.sh from the capture app build directory; \
             start the sidecar manually or rebuild from a checkout that includes it"
        );
        return None;
    };

    let mut command = Command::new(&script);
    command
        .env("GW_SIDECAR_FOREGROUND", "1")
        .env("GW_SIDECAR_HOST", &host)
        .env("GW_SIDECAR_PORT", port.to_string())
        .stdin(Stdio::null())
        .stdout(Stdio::piped())
        .stderr(Stdio::piped());

    let mut child = match command.spawn() {
        Ok(c) => c,
        Err(err) => {
            tracing::error!(
                script = %script.display(),
                %err,
                "failed to spawn sidecar start script; the capture app will run without a managed sidecar"
            );
            return None;
        }
    };

    let pid = child.id();
    tracing::info!(pid, script = %script.display(), kind, "spawned managed sidecar");

    if let Some(out) = child.stdout.take() {
        forward_lines(out, "stdout");
    }
    if let Some(err) = child.stderr.take() {
        forward_lines(err, "stderr");
    }

    Some(ManagedSidecar::new(child))
}
