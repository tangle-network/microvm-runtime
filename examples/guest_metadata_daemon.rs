//! Reference in-guest daemon for the `guest_metadata` host client.
//!
//! Runs **inside the microVM guest** (not the host). It binds a vsock port
//! and services the newline-delimited JSON protocol defined in
//! [`microvm_runtime::guest_metadata`]:
//!
//! - `set_env`  → atomically writes `/var/run/microvm-guest/env`
//! - `set_secret` → writes `/var/run/microvm-guest/secrets/<name>` mode 0600
//! - `ping`     → no-op
//!
//! ## Building
//!
//! ```sh
//! cargo build --release --example guest_metadata_daemon --features firecracker
//! ```
//!
//! The output binary at `target/release/examples/guest_metadata_daemon` is
//! a fully static-ish Linux binary; copy it into your rootfs at e.g.
//! `/usr/sbin/microvm-guest-metadatad` and launch it from init.
//!
//! ## Guest prerequisites
//!
//! - Linux kernel with `CONFIG_VSOCKETS=y` and `CONFIG_VIRTIO_VSOCKETS=y`.
//! - `/dev/vsock` present (created automatically by the virtio-vsock driver).
//! - The state directory (`/var/run/microvm-guest`) must be writable by the
//!   user the daemon runs as. The simplest setup is to launch as root from
//!   init; the daemon will `chmod 0700` the dir on first start.
//!
//! ## CLI
//!
//! ```sh
//! microvm-guest-metadatad [--port N] [--env-file PATH] [--secrets-dir PATH]
//! ```
//!
//! Defaults match the host client (port 5555, `/var/run/microvm-guest/env`,
//! `/var/run/microvm-guest/secrets`). All flags accept overrides for testing.
//!
//! ## Security model
//!
//! The vsock channel is point-to-point between the host VMM and the guest;
//! the network is not reachable through it. The daemon therefore performs
//! no authentication — it trusts every connection from the host. That
//! matches the threat model of the sandbox: the operator owns both ends.
//!
//! What the daemon **does** validate:
//!
//! - Env keys match the POSIX `name` production (`[A-Za-z_][A-Za-z0-9_]*`).
//! - Secret names match `[A-Za-z0-9_-]+` — no `..`, `/`, `.`-prefix, etc.
//! - Atomic file replacement (`write tmp + rename`) so a half-written env
//!   file is never observed by the sandbox sidecar.
//! - Secret files written with mode `0600`.
//!
//! Concurrent connections are accepted but each connection is serviced on
//! its own thread; per-connection requests are sequential.

#![cfg(target_os = "linux")]

use std::collections::HashMap;
use std::fs::{self, File, OpenOptions};
use std::io::{BufRead, BufReader, Write};
use std::os::unix::fs::{OpenOptionsExt, PermissionsExt};
use std::path::{Path, PathBuf};
use std::thread;

use microvm_runtime::guest_metadata::{
    DEFAULT_GUEST_METADATA_PORT, OwnedRequest, Response, base64_decode, validate_env_key,
    validate_secret_name,
};
use vsock::{VMADDR_CID_ANY, VsockListener};

/// Where the env file is materialised. The sandbox sidecar reads this on
/// startup as `KEY=VALUE\n` lines.
const DEFAULT_ENV_FILE: &str = "/var/run/microvm-guest/env";

/// Directory holding `<name>` files; one per pushed secret. Mode 0700.
const DEFAULT_SECRETS_DIR: &str = "/var/run/microvm-guest/secrets";

#[derive(Debug, Clone)]
struct DaemonConfig {
    port: u32,
    env_file: PathBuf,
    secrets_dir: PathBuf,
}

impl Default for DaemonConfig {
    fn default() -> Self {
        Self {
            port: DEFAULT_GUEST_METADATA_PORT,
            env_file: PathBuf::from(DEFAULT_ENV_FILE),
            secrets_dir: PathBuf::from(DEFAULT_SECRETS_DIR),
        }
    }
}

fn main() {
    let cfg = match parse_args() {
        Ok(c) => c,
        Err(e) => {
            eprintln!("microvm-guest-metadatad: {e}");
            print_usage();
            std::process::exit(2);
        }
    };

    if let Err(e) = ensure_state_dirs(&cfg) {
        eprintln!("microvm-guest-metadatad: prepare state dirs: {e}");
        std::process::exit(1);
    }

    let listener = match VsockListener::bind_with_cid_port(VMADDR_CID_ANY, cfg.port) {
        Ok(l) => l,
        Err(e) => {
            eprintln!("microvm-guest-metadatad: bind vsock port {}: {e}", cfg.port);
            std::process::exit(1);
        }
    };
    eprintln!(
        "microvm-guest-metadatad: listening on vsock port {} (env={}, secrets={})",
        cfg.port,
        cfg.env_file.display(),
        cfg.secrets_dir.display()
    );

    for incoming in listener.incoming() {
        match incoming {
            Ok(stream) => {
                let cfg = cfg.clone();
                thread::spawn(move || serve_connection(stream, &cfg));
            }
            Err(e) => {
                eprintln!("microvm-guest-metadatad: accept failed: {e}");
            }
        }
    }
}

fn parse_args() -> Result<DaemonConfig, String> {
    let mut cfg = DaemonConfig::default();
    let mut args = std::env::args().skip(1);
    while let Some(arg) = args.next() {
        match arg.as_str() {
            "--port" => {
                let v = args.next().ok_or("--port requires a value")?;
                cfg.port = v.parse().map_err(|e| format!("invalid --port: {e}"))?;
            }
            "--env-file" => {
                cfg.env_file = PathBuf::from(args.next().ok_or("--env-file requires a value")?);
            }
            "--secrets-dir" => {
                cfg.secrets_dir =
                    PathBuf::from(args.next().ok_or("--secrets-dir requires a value")?);
            }
            "--help" | "-h" => {
                print_usage();
                std::process::exit(0);
            }
            other => return Err(format!("unknown argument: {other}")),
        }
    }
    Ok(cfg)
}

fn print_usage() {
    eprintln!("usage: microvm-guest-metadatad [--port N] [--env-file PATH] [--secrets-dir PATH]");
}

fn ensure_state_dirs(cfg: &DaemonConfig) -> std::io::Result<()> {
    if let Some(parent) = cfg.env_file.parent() {
        fs::create_dir_all(parent)?;
        fs::set_permissions(parent, fs::Permissions::from_mode(0o700))?;
    }
    fs::create_dir_all(&cfg.secrets_dir)?;
    fs::set_permissions(&cfg.secrets_dir, fs::Permissions::from_mode(0o700))?;
    Ok(())
}

fn serve_connection<S>(stream: S, cfg: &DaemonConfig)
where
    S: std::io::Read + std::io::Write + Send + 'static,
{
    // VsockStream is duplex but doesn't implement Clone; wrap reader and
    // writer halves manually.
    let stream = ReadWriteShim(stream);
    let mut reader = BufReader::new(stream);
    loop {
        let mut line = String::new();
        let n = match reader.read_line(&mut line) {
            Ok(n) => n,
            Err(e) => {
                eprintln!("microvm-guest-metadatad: read failed: {e}");
                return;
            }
        };
        if n == 0 {
            return; // peer closed
        }
        let resp = handle_line(line.trim_end_matches(['\r', '\n']), cfg);
        let mut encoded = match serde_json::to_string(&resp) {
            Ok(s) => s,
            Err(e) => {
                eprintln!("microvm-guest-metadatad: encode response: {e}");
                continue;
            }
        };
        encoded.push('\n');
        if let Err(e) = reader.get_mut().write_all(encoded.as_bytes()) {
            eprintln!("microvm-guest-metadatad: write response: {e}");
            return;
        }
    }
}

fn handle_line(line: &str, cfg: &DaemonConfig) -> Response {
    let req: OwnedRequest = match serde_json::from_str(line) {
        Ok(r) => r,
        Err(e) => {
            return Response {
                id: String::new(),
                ok: false,
                error: Some(format!("invalid request json: {e}")),
            };
        }
    };
    let id = req.id().to_string();
    let result = match req {
        OwnedRequest::Ping { .. } => Ok(()),
        OwnedRequest::SetEnv { env, .. } => write_env_file(&cfg.env_file, &env),
        OwnedRequest::SetSecret {
            name, value_b64, ..
        } => write_secret(&cfg.secrets_dir, &name, &value_b64),
    };
    match result {
        Ok(()) => Response {
            id,
            ok: true,
            error: None,
        },
        Err(e) => Response {
            id,
            ok: false,
            error: Some(e),
        },
    }
}

/// Atomically replace the env file. Validates every key before opening the
/// tmp file so a single bad key aborts the entire batch (no partial state).
fn write_env_file(path: &Path, env: &HashMap<String, String>) -> Result<(), String> {
    for k in env.keys() {
        validate_env_key(k).map_err(|e| e.to_string())?;
    }
    let mut keys: Vec<&String> = env.keys().collect();
    keys.sort();
    let mut buf = String::new();
    for k in keys {
        let v = &env[k];
        if v.is_empty() {
            // Empty value deletes the key — emit nothing.
            continue;
        }
        if v.contains('\n') {
            return Err(format!("env value for {k:?} contains newline"));
        }
        buf.push_str(k);
        buf.push('=');
        buf.push_str(v);
        buf.push('\n');
    }
    atomic_write(path, buf.as_bytes(), 0o600)
}

fn write_secret(dir: &Path, name: &str, value_b64: &str) -> Result<(), String> {
    validate_secret_name(name).map_err(|e| e.to_string())?;
    let bytes = base64_decode(value_b64).map_err(|e| e.to_string())?;
    let target = dir.join(name);
    atomic_write(&target, &bytes, 0o600)
}

/// Write `bytes` to `path` atomically via a sibling tmp file + rename.
/// `mode` is applied to the tmp file before rename so the published file
/// is created with the right permissions from the first observable state.
fn atomic_write(path: &Path, bytes: &[u8], mode: u32) -> Result<(), String> {
    let parent = path
        .parent()
        .ok_or_else(|| format!("path has no parent: {}", path.display()))?;
    fs::create_dir_all(parent).map_err(|e| format!("mkdir {}: {e}", parent.display()))?;
    let file_name = path
        .file_name()
        .ok_or_else(|| format!("path has no file name: {}", path.display()))?
        .to_string_lossy()
        .into_owned();
    // Use the PID + a monotonic counter for the tmp suffix so concurrent
    // writers to different targets in the same dir don't collide.
    let tmp = parent.join(format!(".{file_name}.tmp.{}", tmp_suffix()));
    {
        let mut f = OpenOptions::new()
            .write(true)
            .create_new(true)
            .mode(mode)
            .open(&tmp)
            .map_err(|e| format!("open tmp {}: {e}", tmp.display()))?;
        f.write_all(bytes)
            .map_err(|e| format!("write tmp {}: {e}", tmp.display()))?;
        f.sync_all()
            .map_err(|e| format!("fsync tmp {}: {e}", tmp.display()))?;
        drop(f);
    }
    fs::rename(&tmp, path)
        .map_err(|e| format!("rename {} -> {}: {e}", tmp.display(), path.display()))?;
    // Best-effort fsync the parent so the rename is durable across crashes.
    // We deliberately ignore errors — atomic visibility is satisfied even
    // without the dir fsync; this is just durability hardening.
    if let Ok(dir) = File::open(parent) {
        let _ = dir.sync_all();
    }
    Ok(())
}

fn tmp_suffix() -> String {
    use std::sync::atomic::{AtomicU64, Ordering};
    static COUNTER: AtomicU64 = AtomicU64::new(0);
    let n = COUNTER.fetch_add(1, Ordering::Relaxed);
    let pid = std::process::id();
    format!("{pid}-{n}")
}

/// Shim that bridges anything that is `Read + Write` (e.g. `VsockStream`)
/// into the duplex API the daemon needs. Pure pass-through.
struct ReadWriteShim<S>(S);

impl<S: std::io::Read> std::io::Read for ReadWriteShim<S> {
    fn read(&mut self, buf: &mut [u8]) -> std::io::Result<usize> {
        self.0.read(buf)
    }
}

impl<S: std::io::Write> std::io::Write for ReadWriteShim<S> {
    fn write(&mut self, buf: &[u8]) -> std::io::Result<usize> {
        self.0.write(buf)
    }
    fn flush(&mut self) -> std::io::Result<()> {
        self.0.flush()
    }
}
