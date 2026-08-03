use futures_util::{SinkExt, StreamExt};
use std::{
    collections::HashMap,
    env,
    ffi::OsString,
    fs,
    io::{self, Write},
    path::{Path, PathBuf},
    process::Command,
    sync::{
        Arc, OnceLock,
        atomic::{AtomicU64, Ordering},
    },
    time::{Duration, Instant, SystemTime},
};
use tokio::{
    io::{AsyncReadExt, AsyncWriteExt},
    net::{TcpStream, UdpSocket},
    sync::{Mutex, RwLock, mpsc},
};
use tokio_tungstenite::{connect_async, tungstenite::Message};
use tracing_subscriber::prelude::*;
use tracing_subscriber::{EnvFilter, reload};
use tunnel_protocol::{
    AgentSettings, ControlMessage, PROTOCOL_VERSION, TunnelKind, TunnelSpec, decode,
    decode_stream_data, encode, encode_stream_data,
};
use url::Url;

/// Enrollment pairing code alphabet and length; the same constants live in the
/// server so both sides agree on what a valid code looks like.
const ENROLL_CODE_LEN: usize = 8;
const ENROLL_CODE_ALPHABET: &[u8] = b"23456789ABCDEFGHJKMNPQRSTUVWXYZ";

/// Runtime hook for the tracing filter so `SettingsSync` can change the log
/// level without restarting the process. The concrete reload handle is hidden
/// inside the closure to avoid naming the full subscriber type.
static LOG_FILTER: OnceLock<Arc<dyn Fn(&str) + Send + Sync>> = OnceLock::new();

type StreamMap = Arc<RwLock<HashMap<u128, mpsc::Sender<Vec<u8>>>>>;
type ConnectionMap = Arc<RwLock<HashMap<u128, ConnectionInfo>>>;
type DataSenderMap = Arc<RwLock<HashMap<u16, mpsc::Sender<Message>>>>;
type TaskMap = Arc<tokio::sync::Mutex<HashMap<u128, tokio::task::JoinHandle<()>>>>;
type PendingMap = Arc<RwLock<HashMap<u128, (Instant, Vec<Vec<u8>>)>>>;

/// Upper bound on frames buffered for one stream that has not been registered
/// yet. `StreamOpen` travels on the control socket while data frames use data
/// sockets, so the first frames can arrive first; the race window is a few
/// milliseconds, so this cap is never approached in practice.
const PENDING_STREAM_FRAMES: usize = 64;

/// Shared runtime state for the agent process. `settings` holds the latest
/// server-pushed effective configuration; local bootstrap values only apply
/// until the first `SettingsSync`.
#[derive(Clone)]
struct AgentStatus {
    specs: Arc<RwLock<HashMap<String, TunnelSpec>>>,
    connections: ConnectionMap,
    data_channels: DataSenderMap,
    bandwidth: BandwidthLimiter,
    settings: Arc<RwLock<AgentSettings>>,
}

impl AgentStatus {
    fn new(config: &AgentConfig) -> Self {
        Self {
            specs: Arc::new(RwLock::new(HashMap::new())),
            connections: Arc::new(RwLock::new(HashMap::new())),
            data_channels: Arc::new(RwLock::new(HashMap::new())),
            bandwidth: BandwidthLimiter::default(),
            settings: Arc::new(RwLock::new(config.to_agent_settings())),
        }
    }
}

#[derive(Clone)]
struct ConnectionInfo {
    kind: String,
}

/// Connection parameters for one agent run. Values come from environment
/// variables, the bootstrap `agent.env`, and the credentials file with safe
/// defaults. Once the server pushes `SettingsSync`, the credentials file
/// becomes authoritative for the next session.
#[derive(Clone)]
struct AgentConfig {
    server: String,
    data_server: String,
    token: String,
    name: String,
    data_channels: u16,
    heartbeat_secs: u64,
    pong_timeout_secs: u64,
    reconnect_min_secs: u64,
    reconnect_max_secs: u64,
    log_level: String,
}

impl AgentConfig {
    fn from_env() -> Self {
        let file = load_file_config();
        let credentials = load_credentials();
        let server = env::var("TUNNEL_SERVER_URL")
            .ok()
            .or_else(|| credentials.get("SERVER_URL").cloned())
            .or_else(|| file.get("TUNNEL_SERVER_URL").cloned())
            .unwrap_or_else(|| "ws://127.0.0.1:18080/control".into());
        let token = env::var("TUNNEL_TOKEN")
            .ok()
            .or_else(|| credentials.get("TOKEN").cloned())
            .or_else(|| file.get("TUNNEL_TOKEN").cloned())
            .unwrap_or_default();
        let name = credentials
            .get("DEVICE_NAME")
            .cloned()
            .or_else(|| env::var("COMPUTERNAME").ok())
            .unwrap_or_else(|| "Windows agent".into());
        let data_server = Url::parse(&server)
            .map(|mut url| {
                url.set_path("/data");
                url.to_string()
            })
            .unwrap_or_else(|_| format!("{}/data", server.trim_end_matches('/')));
        let data_channels = pick_num(&["DATA_CHANNELS"], &[&credentials, &file], 2, 1, 8) as u16;
        let heartbeat_secs = pick_num(
            &["HEARTBEAT_SECS", "AGENT_HEARTBEAT_SECS"],
            &[&credentials, &file],
            10,
            3,
            60,
        );
        let pong_timeout_secs = pick_num(
            &["PONG_TIMEOUT_SECS", "AGENT_PONG_TIMEOUT_SECS"],
            &[&credentials, &file],
            25,
            5,
            300,
        );
        let reconnect_min_secs = pick_num(
            &["RECONNECT_MIN_SECS", "AGENT_RECONNECT_MIN_SECS"],
            &[&credentials, &file],
            1,
            1,
            60,
        );
        let reconnect_max_secs = pick_num(
            &["RECONNECT_MAX_SECS", "AGENT_RECONNECT_MAX_SECS"],
            &[&credentials, &file],
            10,
            1,
            300,
        )
        .max(reconnect_min_secs);
        let log_level = credentials
            .get("LOG_LEVEL")
            .cloned()
            .or_else(|| file.get("LOG_LEVEL").cloned())
            .or_else(|| env::var("AGENT_LOG_LEVEL").ok())
            .filter(|level| {
                matches!(
                    level.as_str(),
                    "error" | "warn" | "info" | "debug" | "trace"
                )
            })
            .unwrap_or_else(|| "info".into());
        Self {
            server,
            data_server,
            token,
            name,
            data_channels,
            heartbeat_secs,
            pong_timeout_secs,
            reconnect_min_secs,
            reconnect_max_secs,
            log_level,
        }
    }

    fn to_agent_settings(&self) -> AgentSettings {
        AgentSettings {
            device_name: self.name.clone(),
            server_url: self.server.clone(),
            data_channels: self.data_channels,
            heartbeat_secs: self.heartbeat_secs,
            pong_timeout_secs: self.pong_timeout_secs,
            reconnect_min_secs: self.reconnect_min_secs,
            reconnect_max_secs: self.reconnect_max_secs,
            log_level: self.log_level.clone(),
        }
    }
}

/// Picks the first valid number from `keys` across `sources` (credentials
/// first, then the bootstrap file), falling back to `default`.
fn pick_num(
    keys: &[&str],
    sources: &[&HashMap<String, String>],
    default: u64,
    min: u64,
    max: u64,
) -> u64 {
    for key in keys {
        for source in sources {
            if let Some(value) = source
                .get(*key)
                .and_then(|value| value.parse::<u64>().ok())
                .filter(|value| *value >= min && *value <= max)
            {
                return value;
            }
        }
    }
    default
}

fn generate_enroll_code() -> String {
    let bytes = uuid::Uuid::new_v4();
    bytes
        .as_bytes()
        .iter()
        .take(ENROLL_CODE_LEN)
        .map(|byte| {
            ENROLL_CODE_ALPHABET[(byte % ENROLL_CODE_ALPHABET.len() as u8) as usize] as char
        })
        .collect()
}

/// Backoff before the next reconnect attempt: exponential growth from `min` up
/// to `max`, scaled by a caller-provided jitter fraction (0.7..=1.3).
fn reconnect_delay(attempt: u32, min_secs: u64, max_secs: u64, jitter: f64) -> Duration {
    let growth = 2_f64.powi(attempt.min(5) as i32);
    let base = (min_secs as f64 * growth).min(max_secs as f64);
    Duration::from_secs_f64((base * jitter).max(0.1))
}

/// Shared token bucket that throttles the agent's outbound (agent -> server)
/// direction so the single WebSocket channel can never be saturated by TCP or
/// UDP data. 0 disables throttling; the server pushes the cap via
/// `ControlMessage::BandwidthConfig`.
#[derive(Clone)]
struct BandwidthLimiter {
    mbps: Arc<AtomicU64>,
    state: Arc<Mutex<BucketState>>,
}

struct BucketState {
    tokens: f64,
    last: Instant,
}

impl Default for BandwidthLimiter {
    fn default() -> Self {
        Self::new(0)
    }
}

impl BandwidthLimiter {
    fn new(mbps: u64) -> Self {
        Self {
            mbps: Arc::new(AtomicU64::new(mbps)),
            state: Arc::new(Mutex::new(BucketState {
                tokens: mbps as f64 * 1_000_000.0 / 8.0,
                last: Instant::now(),
            })),
        }
    }

    fn set_mbps(&self, mbps: u64) {
        self.mbps.store(mbps, Ordering::Relaxed);
    }

    async fn acquire(&self, bytes: usize) {
        if self.mbps.load(Ordering::Relaxed) == 0 {
            return;
        }
        let mut state = self.state.lock().await;
        loop {
            let mbps = self.mbps.load(Ordering::Relaxed);
            if mbps == 0 {
                return;
            }
            let rate = mbps as f64 * 1_000_000.0 / 8.0;
            let burst = rate;
            let now = Instant::now();
            let elapsed = now.duration_since(state.last).as_secs_f64();
            state.last = now;
            state.tokens = (state.tokens + elapsed * rate).min(burst);
            if state.tokens >= bytes as f64 {
                state.tokens -= bytes as f64;
                return;
            }
            let wait = (bytes as f64 - state.tokens) / rate;
            drop(state);
            tokio::time::sleep(Duration::from_secs_f64(wait.min(0.5))).await;
            state = self.state.lock().await;
        }
    }
}

fn kind_str(kind: &TunnelKind) -> &'static str {
    match kind {
        TunnelKind::Tcp => "tcp",
        TunnelKind::Http => "http",
        TunnelKind::Udp => "udp",
    }
}

/// Server-issued credentials and pushed settings live in a single key/value
/// file so the agent can reconnect unattended. The operator never sees or
/// types the token; on Windows the file is locked down to SYSTEM/Administrators.
fn credentials_path() -> PathBuf {
    if let Some(path) = env::var_os("TUNNEL_CREDENTIALS_FILE") {
        return PathBuf::from(path);
    }
    #[cfg(windows)]
    {
        if let Some(root) = env::var_os("PROGRAMDATA") {
            return PathBuf::from(root)
                .join("TunnelControl")
                .join("credentials");
        }
    }
    env::current_exe()
        .ok()
        .and_then(|exe| exe.parent().map(|parent| parent.join("credentials")))
        .unwrap_or_else(|| PathBuf::from("credentials"))
}

fn parse_key_value(content: &str) -> HashMap<String, String> {
    content
        .lines()
        .filter_map(|line| line.split_once('='))
        .map(|(key, value)| (key.trim().to_owned(), value.trim().to_owned()))
        .collect()
}

fn load_credentials() -> HashMap<String, String> {
    fs::read_to_string(credentials_path())
        .map(|content| parse_key_value(&content))
        .unwrap_or_default()
}

/// Merges `updates` into the credentials file. Empty values remove the key so
/// e.g. a consumed enrollment code is cleared, not stored as blank.
fn save_credentials(updates: &HashMap<String, String>) -> io::Result<()> {
    let path = credentials_path();
    if let Some(parent) = path.parent() {
        fs::create_dir_all(parent)?;
    }
    let mut map = load_credentials();
    for (key, value) in updates {
        if value.is_empty() {
            map.remove(key);
        } else {
            map.insert(key.clone(), value.clone());
        }
    }
    let mut content = String::new();
    for (key, value) in map {
        content.push_str(&format!("{key}={value}\n"));
    }
    fs::write(&path, content)?;
    restrict_credentials(&path);
    Ok(())
}

#[cfg(windows)]
fn restrict_credentials(path: &Path) {
    // SYSTEM + Administrators cover the Windows service; the interactive user
    // keeps access so console mode can still re-read the file after saving.
    let current_user = Command::new("whoami")
        .output()
        .ok()
        .map(|output| String::from_utf8_lossy(&output.stdout).trim().to_string())
        .filter(|user| !user.is_empty());
    let mut args: Vec<String> = vec![
        "/inheritance:r".into(),
        "/grant:r".into(),
        "SYSTEM:(F)".into(),
        "/grant:r".into(),
        "Administrators:(F)".into(),
    ];
    if let Some(user) = current_user {
        args.push("/grant:r".into());
        args.push(format!("{user}:(F)"));
    }
    let _ = Command::new("icacls").arg(path).args(&args).status();
}

#[cfg(not(windows))]
fn restrict_credentials(_path: &Path) {}

/// Applies a pushed log level to the running filter; failures are ignored so
/// a bad value never takes the agent down.
fn apply_log_level(level: &str) {
    if let Some(handle) = LOG_FILTER.get() {
        handle(level);
    }
}

#[cfg(windows)]
use windows_service::{
    define_windows_service,
    service::{
        ServiceControl, ServiceControlAccept, ServiceExitCode, ServiceState, ServiceStatus,
        ServiceType,
    },
    service_control_handler::{self, ServiceControlHandlerResult},
};

#[cfg(windows)]
define_windows_service!(ffi_service_main, service_main);

fn main() {
    let arguments: Vec<String> = env::args().collect();
    if arguments.iter().any(|argument| argument == "--service") {
        setup_logging(false);
        #[cfg(windows)]
        {
            if let Err(error) =
                windows_service::service_dispatcher::start("TunnelAgent", ffi_service_main)
            {
                eprintln!("Service dispatcher failed: {error}");
                std::process::exit(1);
            }
            return;
        }
        #[cfg(not(windows))]
        {
            let _ = arguments;
            eprintln!("Service mode is only supported on Windows");
            std::process::exit(1);
        }
    }
    if arguments.iter().any(|argument| argument == "--uninstall") {
        setup_logging(false);
        if let Err(error) = uninstall_service() {
            eprintln!("Uninstall failed: {error}");
            std::process::exit(1);
        }
        return;
    }
    if arguments.iter().any(|argument| argument == "--install") {
        setup_logging(true);
        let server = arguments
            .iter()
            .position(|argument| argument == "--server")
            .and_then(|index| arguments.get(index + 1))
            .cloned();
        if let Err(error) = install_service(server.as_deref()) {
            eprintln!("Installation failed: {error}");
            std::process::exit(1);
        }
        return;
    }
    if arguments.get(1).map(String::as_str) == Some("logs") {
        let follow = arguments
            .iter()
            .any(|argument| argument == "-f" || argument == "--follow");
        let lines = arguments
            .iter()
            .position(|argument| argument == "-n")
            .and_then(|index| arguments.get(index + 1))
            .and_then(|value| value.parse::<usize>().ok())
            .unwrap_or(100)
            .clamp(1, 2000);
        main_logs(follow, lines);
        return;
    }
    setup_logging(true);
    if !arguments.iter().any(|argument| argument == "--agent") {
        if let Err(error) = install_service(None) {
            eprintln!("Installation failed: {error}");
            std::process::exit(1);
        }
        return;
    }
    run_agent_forever();
}

/// Initializes tracing. Console mode keeps stdout output and mirrors it into
/// the rotating file; service mode writes only to the file. When the log
/// directory is unusable, logging falls back to console output alone. The
/// filter layer is reloadable so `SettingsSync` can change the level live.
fn setup_logging(console: bool) {
    let initial_level = load_credentials()
        .get("LOG_LEVEL")
        .cloned()
        .unwrap_or_else(|| "info".into());
    let (filter_layer, filter_handle) = reload::Layer::new(
        EnvFilter::try_new(&initial_level).unwrap_or_else(|_| EnvFilter::new("info")),
    );
    let file_layer = create_file_writer().map(|writer| {
        tracing_subscriber::fmt::layer()
            .with_writer(writer)
            .with_ansi(false)
    });
    let stdout_layer = console.then(|| tracing_subscriber::fmt::layer().with_ansi(true));
    let subscriber = tracing_subscriber::registry()
        .with(stdout_layer)
        .with(file_layer)
        .with(filter_layer);
    let _ = tracing::subscriber::set_global_default(subscriber);
    let _ = LOG_FILTER.set(Arc::new(move |level: &str| {
        if let Ok(filter) = EnvFilter::try_new(level) {
            let _ = filter_handle.modify(|current| *current = filter);
        }
    }));
}

/// Resolves the rotating log directory: `TUNNEL_LOG_DIR` overrides the default
/// `%PROGRAMDATA%\TunnelControl\logs` on Windows. Returns None on non-Windows
/// builds without an explicit override so development runs keep stdout only.
fn log_dir() -> Option<PathBuf> {
    if let Some(dir) = env::var_os("TUNNEL_LOG_DIR") {
        return Some(PathBuf::from(dir));
    }
    #[cfg(windows)]
    {
        env::var_os("PROGRAMDATA")
            .map(|root| PathBuf::from(root).join("TunnelControl").join("logs"))
    }
    #[cfg(not(windows))]
    None
}

/// Creates the log directory and a non-blocking file writer for
/// `agent.log` with daily rotation. The worker guard is leaked so the writer
/// stays alive for the whole process.
fn create_file_writer() -> Option<tracing_appender::non_blocking::NonBlocking> {
    let dir = log_dir()?;
    if let Err(error) = fs::create_dir_all(&dir) {
        eprintln!("agent log directory {dir:?} unavailable ({error}); logging to console only");
        return None;
    }
    clean_old_logs(&dir);
    let appender = tracing_appender::rolling::daily(&dir, "agent.log");
    let (writer, guard) = tracing_appender::non_blocking(appender);
    Box::leak(Box::new(guard));
    Some(writer)
}

/// Deletes rotated agent log files older than seven days; runs at startup.
fn clean_old_logs(dir: &Path) {
    let Ok(entries) = fs::read_dir(dir) else {
        return;
    };
    let now = SystemTime::now();
    let retention = Duration::from_secs(7 * 24 * 60 * 60);
    for entry in entries.flatten() {
        let name = entry.file_name();
        if !name.to_string_lossy().starts_with("agent.log.") {
            continue;
        }
        let modified = entry
            .metadata()
            .and_then(|meta| meta.modified())
            .unwrap_or(now);
        if now.duration_since(modified).unwrap_or(Duration::ZERO) > retention {
            let _ = fs::remove_file(entry.path());
        }
    }
}

#[cfg(windows)]
fn service_main(_arguments: Vec<OsString>) {
    let (stop_tx, stop_rx) = std::sync::mpsc::channel::<()>();
    let event_handler = move |control_event| -> ServiceControlHandlerResult {
        match control_event {
            ServiceControl::Stop => {
                let _ = stop_tx.send(());
                ServiceControlHandlerResult::NoError
            }
            ServiceControl::Interrogate => ServiceControlHandlerResult::NoError,
            _ => ServiceControlHandlerResult::NotImplemented,
        }
    };
    let status_handle = match service_control_handler::register("TunnelAgent", event_handler) {
        Ok(handle) => handle,
        Err(error) => {
            eprintln!("Failed to register service control handler: {error}");
            return;
        }
    };
    let running = ServiceStatus {
        service_type: ServiceType::OWN_PROCESS,
        current_state: ServiceState::Running,
        controls_accepted: ServiceControlAccept::STOP,
        exit_code: ServiceExitCode::Win32(0),
        checkpoint: 0,
        wait_hint: Duration::default(),
        process_id: None,
    };
    if status_handle.set_service_status(running.clone()).is_err() {
        return;
    }
    std::thread::spawn(run_agent_forever);
    let _ = stop_rx.recv();
    let stopped = ServiceStatus {
        current_state: ServiceState::Stopped,
        ..running
    };
    let _ = status_handle.set_service_status(stopped);
}

fn run_agent_forever() {
    let runtime = tokio::runtime::Builder::new_multi_thread()
        .enable_all()
        .build()
        .expect("failed to build tokio runtime");
    runtime.block_on(async move {
        let mut attempt = 0_u32;
        let mut jitter = 0_u64;
        loop {
            // Re-read the config every session so enrollment and pushed
            // settings (persisted to the credentials file) take effect on the
            // next connect without a process restart.
            let config = AgentConfig::from_env();
            let status = AgentStatus::new(&config);
            let outcome = run(&config, &status).await;
            match outcome {
                // Enrollment approved or settings require a reconnect:
                // connect again immediately with the fresh config.
                Ok(RunOutcome::ReconnectNow) => {
                    attempt = 0;
                    continue;
                }
                Ok(RunOutcome::Disconnected) => {
                    tracing::info!("control connection closed; backing off");
                }
                Err(error) => {
                    tracing::warn!(%error, "agent disconnected; retrying");
                }
            }
            jitter = jitter.wrapping_add(17).wrapping_mul(31);
            let fraction = 0.7 + (jitter % 61) as f64 / 100.0;
            let delay = reconnect_delay(
                attempt,
                config.reconnect_min_secs,
                config.reconnect_max_secs,
                fraction,
            );
            attempt = attempt.saturating_add(1);
            tracing::info!(seconds = delay.as_secs_f64(), "retrying control connection");
            tokio::time::sleep(delay).await;
        }
    });
}

/// `logs` CLI: prints recent agent log lines and optionally follows the
/// newest file. This is the replacement for the removed GUI log panel.
fn main_logs(follow: bool, lines: usize) {
    let Some(dir) = log_dir() else {
        eprintln!("No agent log directory is configured for this machine.");
        std::process::exit(1);
    };
    let mut printed: HashMap<PathBuf, usize> = HashMap::new();
    loop {
        let files = sorted_log_files(&dir);
        let Some(newest) = files.first() else {
            eprintln!("No agent.log files found under {dir:?}");
            if !follow {
                return;
            }
            std::thread::sleep(Duration::from_secs(1));
            continue;
        };
        if !printed.contains_key(newest) {
            // First pass: print the tail of the newest few files, newest last
            // so the output reads chronologically.
            let mut combined: Vec<String> = Vec::new();
            for path in files.iter().rev().take(3) {
                if let Ok(content) = fs::read_to_string(path) {
                    combined.extend(content.lines().map(|line| line.to_string()));
                }
            }
            let start = combined.len().saturating_sub(lines);
            for line in combined.into_iter().skip(start) {
                println!("{line}");
            }
            printed.insert(
                newest.clone(),
                fs::read_to_string(newest)
                    .map(|content| content.lines().count())
                    .unwrap_or(0),
            );
        } else if let Ok(content) = fs::read_to_string(newest) {
            let count = content.lines().count();
            let previous = printed.get(newest).copied().unwrap_or(0);
            if count > previous {
                for line in content.lines().skip(previous) {
                    println!("{line}");
                }
                printed.insert(newest.clone(), count);
            }
        }
        if !follow {
            return;
        }
        std::thread::sleep(Duration::from_secs(1));
    }
}

fn sorted_log_files(dir: &Path) -> Vec<PathBuf> {
    let mut files: Vec<PathBuf> = fs::read_dir(dir)
        .map(|read_dir| {
            read_dir
                .flatten()
                .filter(|entry| entry.file_name().to_string_lossy().starts_with("agent.log"))
                .map(|entry| entry.path())
                .collect()
        })
        .unwrap_or_default();
    files.sort_by_key(|path| {
        fs::metadata(path)
            .and_then(|meta| meta.modified())
            .ok()
            .and_then(|time| time.duration_since(SystemTime::UNIX_EPOCH).ok())
            .map(|duration| duration.as_secs())
            .unwrap_or(0)
    });
    files.reverse();
    files
}

/// Installs the Windows service. `server` may come from `--server` or an
/// interactive prompt; a token is deliberately NOT requested because the
/// device-code enrollment flow issues one after the admin approves the agent.
fn install_service(server: Option<&str>) -> Result<(), Box<dyn std::error::Error>> {
    #[cfg(not(windows))]
    return Err("The installer is only supported on Windows".into());

    #[cfg(windows)]
    {
        let server_url = match server {
            Some(value) => value.trim().to_string(),
            None => {
                let mut input = String::new();
                print!("Server WebSocket URL (example: ws://203.0.113.10:18080/control): ");
                io::stdout().flush()?;
                io::stdin().read_line(&mut input)?;
                input.trim().to_string()
            }
        };
        if server_url.is_empty() {
            return Err("Server URL is required".into());
        }
        let install_root = PathBuf::from(env::var("ProgramFiles")?).join("TunnelControl");
        fs::create_dir_all(&install_root)?;
        let agent_path = install_root.join("tunnel-agent.exe");
        fs::copy(env::current_exe()?, &agent_path)?;
        // Preserve a legacy TUNNEL_TOKEN if one exists; otherwise the agent
        // starts in device-code enrollment mode.
        let legacy = load_file_config();
        let legacy_token = legacy
            .get("TUNNEL_TOKEN")
            .map(|token| format!("TUNNEL_TOKEN={token}\n"))
            .unwrap_or_default();
        fs::write(
            install_root.join("agent.env"),
            format!("TUNNEL_SERVER_URL={server_url}\n{legacy_token}"),
        )?;
        let service = "TunnelAgent";
        let _ = Command::new("sc.exe").args(["stop", service]).status();
        let _ = Command::new("sc.exe").args(["delete", service]).status();
        let binary_path = format!("\"{}\" --service", agent_path.display());
        let status = Command::new("sc.exe")
            .args([
                "create",
                service,
                "binPath=",
                &binary_path,
                "start=",
                "auto",
                "DisplayName=",
                "Tunnel Control Agent",
            ])
            .status()?;
        if !status.success() {
            return Err(
                "Could not create the Windows service. Run this installer as Administrator.".into(),
            );
        }
        let _ = Command::new("sc.exe")
            .args([
                "failure",
                service,
                "reset=",
                "86400",
                "actions=",
                "restart/5000/restart/10000/restart/30000",
            ])
            .status();
        let status = Command::new("sc.exe").args(["start", service]).status()?;
        if !status.success() {
            return Err(
                "Service was installed but did not start. Check Windows Event Viewer.".into(),
            );
        }
        println!("TunnelAgent service installed and started.");
        println!("Run 'tunnel-agent.exe logs' to follow the service log.");
        Ok(())
    }
}

/// Stops and removes the Windows service and clears machine-level bootstrap
/// environment variables. Local credentials are kept so a reinstall reuses
/// the issued token.
fn uninstall_service() -> Result<(), Box<dyn std::error::Error>> {
    #[cfg(not(windows))]
    return Err("Service uninstall is only supported on Windows".into());

    #[cfg(windows)]
    {
        let service = "TunnelAgent";
        let _ = Command::new("sc.exe").args(["stop", service]).status();
        let _ = Command::new("sc.exe").args(["delete", service]).status();
        let _ = Command::new("setx")
            .args(["TUNNEL_SERVER_URL", ""])
            .status();
        let _ = Command::new("setx").args(["TUNNEL_TOKEN", ""]).status();
        println!("TunnelAgent service removed.");
        Ok(())
    }
}

fn load_file_config() -> HashMap<String, String> {
    let path = env::current_exe()
        .ok()
        .and_then(|exe| exe.parent().map(|parent| parent.join("agent.env")))
        .unwrap_or_else(|| PathBuf::from("agent.env"));
    fs::read_to_string(path)
        .unwrap_or_default()
        .lines()
        .filter_map(|line| line.split_once('='))
        .map(|(key, value)| (key.trim().to_owned(), value.trim().to_owned()))
        .collect()
}

enum RunOutcome {
    /// Enrollment approved or settings changed in a way that needs a new
    /// control session (server_url / data_channels / token); reconnect now
    /// without backoff.
    ReconnectNow,
    /// The control channel closed or errored; the outer loop applies backoff.
    Disconnected,
}

async fn run(
    config: &AgentConfig,
    status: &AgentStatus,
) -> Result<RunOutcome, Box<dyn std::error::Error>> {
    if config.token.is_empty() {
        run_enroll(config).await?;
        return Ok(RunOutcome::ReconnectNow);
    }
    let (socket, _) = connect_async(&config.server).await?;
    enable_tcp_keepalive(&socket);
    tracing::info!(server = %config.server, "control connection established");
    let (mut write, mut read) = socket.split();
    // Control messages (register, heartbeat, ping, probe results, close) use a
    // dedicated channel; tunnel payload moves over separate data channels, so
    // a data burst can never starve the keepalive or the control plane.
    let (control_tx, mut control_rx) = mpsc::channel::<Message>(256);
    let specs = status.specs.clone();
    let streams: StreamMap = Arc::new(RwLock::new(HashMap::new()));
    let connections = status.connections.clone();
    let data_channels = status.data_channels.clone();
    let bandwidth = status.bandwidth.clone();
    let pending: PendingMap = Arc::new(RwLock::new(HashMap::new()));
    let bridge_tasks: TaskMap = Arc::new(tokio::sync::Mutex::new(HashMap::new()));
    let data_tasks: Arc<tokio::sync::Mutex<Vec<tokio::task::JoinHandle<()>>>> =
        Arc::new(tokio::sync::Mutex::new(Vec::new()));
    let last_pong = Arc::new(std::sync::Mutex::new(Instant::now()));
    let reader_done = Arc::new(tokio::sync::Notify::new());
    let settings_changed = Arc::new(tokio::sync::Notify::new());

    let register = ControlMessage::Register {
        version: PROTOCOL_VERSION,
        token: config.token.clone(),
        device_name: config.name.clone(),
    };
    control_tx
        .send(Message::Text(String::from_utf8(encode(&register)?)?.into()))
        .await?;
    let writer_done = reader_done.clone();
    let writer_task = tokio::spawn(async move {
        while let Some(message) = control_rx.recv().await {
            if write.send(message).await.is_err() {
                break;
            }
        }
        writer_done.notify_one();
    });

    let reader_control = control_tx.clone();
    let reader_specs = specs.clone();
    let reader_streams = streams.clone();
    let reader_connections = connections.clone();
    let reader_data_channels = data_channels.clone();
    let reader_bandwidth = bandwidth.clone();
    let reader_bridge_tasks = bridge_tasks.clone();
    let reader_pending = pending.clone();
    let reader_pong = last_pong.clone();
    let reader_config = config.clone();
    let reader_status = status.clone();
    let reader_data_tasks = data_tasks.clone();
    let reader_done_notify = reader_done.clone();
    let reader_settings_changed = settings_changed.clone();
    let reader_task = tokio::spawn(async move {
        let mut data_channels_opened = false;
        while let Some(Ok(message)) = read.next().await {
            match message {
                Message::Pong(_) => {
                    if let Ok(mut guard) = reader_pong.lock() {
                        *guard = Instant::now();
                    }
                }
                Message::Text(text) => match decode(text.as_bytes()) {
                    Ok(ControlMessage::Registered { tunnels, .. })
                    | Ok(ControlMessage::SyncTunnels { tunnels }) => {
                        let mut map = reader_specs.write().await;
                        *map = tunnels.into_iter().map(|t| (t.id.clone(), t)).collect();
                        tracing::info!(count = map.len(), "tunnel configuration synchronized");
                        if !data_channels_opened {
                            data_channels_opened = true;
                            // Drop any stale channel entries left by a previous
                            // run, then open a fresh set for this session.
                            reader_data_channels.write().await.clear();
                            for _ in 0..reader_config.data_channels {
                                let task = tokio::spawn(data_channel_task(
                                    reader_config.clone(),
                                    reader_status.clone(),
                                    reader_streams.clone(),
                                    reader_connections.clone(),
                                    reader_control.clone(),
                                    reader_pending.clone(),
                                ));
                                reader_data_tasks.lock().await.push(task);
                            }
                        }
                    }
                    Ok(ControlMessage::BandwidthConfig { mbps }) => {
                        reader_bandwidth.set_mbps(mbps);
                        tracing::info!(mbps, "server bandwidth limit applied");
                    }
                    Ok(ControlMessage::SettingsSync { settings }) => {
                        let current = reader_status.settings.read().await.clone();
                        // Fields that cannot change live require a reconnect;
                        // everything else applies immediately.
                        let reconnect_required = settings.server_url != current.server_url
                            || settings.data_channels != current.data_channels;
                        let mut updates = HashMap::new();
                        updates.insert("SERVER_URL".to_string(), settings.server_url.clone());
                        updates.insert("DEVICE_NAME".to_string(), settings.device_name.clone());
                        updates.insert(
                            "DATA_CHANNELS".to_string(),
                            settings.data_channels.to_string(),
                        );
                        updates.insert(
                            "HEARTBEAT_SECS".to_string(),
                            settings.heartbeat_secs.to_string(),
                        );
                        updates.insert(
                            "PONG_TIMEOUT_SECS".to_string(),
                            settings.pong_timeout_secs.to_string(),
                        );
                        updates.insert(
                            "RECONNECT_MIN_SECS".to_string(),
                            settings.reconnect_min_secs.to_string(),
                        );
                        updates.insert(
                            "RECONNECT_MAX_SECS".to_string(),
                            settings.reconnect_max_secs.to_string(),
                        );
                        updates.insert("LOG_LEVEL".to_string(), settings.log_level.clone());
                        if save_credentials(&updates).is_err() {
                            tracing::warn!("could not persist pushed settings");
                        }
                        apply_log_level(&settings.log_level);
                        *reader_status.settings.write().await = settings;
                        tracing::info!("server settings applied");
                        if reconnect_required {
                            reader_settings_changed.notify_one();
                        }
                    }
                    Ok(ControlMessage::TokenRotate { token }) => {
                        let mut updates = HashMap::new();
                        updates.insert("TOKEN".to_string(), token);
                        updates.insert("ENROLL_CODE".to_string(), String::new());
                        if save_credentials(&updates).is_err() {
                            tracing::warn!("could not persist rotated token");
                        }
                        tracing::info!("device token rotated; reconnecting");
                        reader_settings_changed.notify_one();
                    }
                    Ok(ControlMessage::StreamOpen {
                        stream_id,
                        tunnel_id,
                        data_channel,
                    }) => {
                        let Ok(id) = stream_id.parse::<u128>() else {
                            continue;
                        };
                        let spec = reader_specs.read().await.get(&tunnel_id).cloned();
                        let Some(spec) = spec else {
                            send_close(&reader_control, stream_id, Some("unknown_tunnel".into()));
                            continue;
                        };
                        let channel_tx = reader_data_channels
                            .read()
                            .await
                            .get(&data_channel)
                            .cloned();
                        let Some(channel_tx) = channel_tx else {
                            send_close(
                                &reader_control,
                                stream_id,
                                Some("data_channel_unavailable".into()),
                            );
                            continue;
                        };
                        let (tx, rx) = mpsc::channel::<Vec<u8>>(128);
                        // Register the stream before spawning the bridge so the
                        // first data frame following StreamOpen is never dropped.
                        reader_streams.write().await.insert(id, tx.clone());
                        reader_connections.write().await.insert(
                            id,
                            ConnectionInfo {
                                kind: kind_str(&spec.kind).to_string(),
                            },
                        );
                        tracing::info!(
                            stream_id = %id,
                            tunnel_id = %tunnel_id,
                            data_channel,
                            public_port = spec.public_port,
                            "stream opened"
                        );
                        // Flush frames that arrived on a data socket before
                        // this StreamOpen was processed (cross-connection
                        // ordering is not guaranteed).
                        let buffered = reader_pending
                            .write()
                            .await
                            .remove(&id)
                            .map(|(_, frames)| frames)
                            .unwrap_or_default();
                        for frame in buffered {
                            if tx.send(frame).await.is_err() {
                                break;
                            }
                        }
                        let control = reader_control.clone();
                        let limiter = reader_bandwidth.clone();
                        let streams = reader_streams.clone();
                        let connections = reader_connections.clone();
                        let task = tokio::spawn(async move {
                            match spec.kind {
                                TunnelKind::Udp => {
                                    bridge_local_udp(
                                        id,
                                        spec,
                                        rx,
                                        channel_tx,
                                        control,
                                        streams,
                                        connections,
                                        limiter,
                                    )
                                    .await;
                                }
                                _ => {
                                    bridge_local(
                                        id,
                                        spec,
                                        rx,
                                        channel_tx,
                                        control,
                                        streams,
                                        connections,
                                        limiter,
                                    )
                                    .await
                                }
                            }
                        });
                        reader_bridge_tasks.lock().await.insert(id, task);
                    }
                    Ok(ControlMessage::StreamClose { stream_id, reason }) => {
                        if let Ok(id) = stream_id.parse::<u128>() {
                            tracing::info!(
                                stream_id = %stream_id,
                                reason = reason.as_deref().unwrap_or("server_close"),
                                "stream closed"
                            );
                            reader_streams.write().await.remove(&id);
                            reader_connections.write().await.remove(&id);
                            reader_pending.write().await.remove(&id);
                            if let Some(task) = reader_bridge_tasks.lock().await.remove(&id) {
                                task.abort();
                            }
                        }
                    }
                    Ok(ControlMessage::ProbeLocal {
                        probe_id,
                        tunnel_id,
                    }) => {
                        let spec = reader_specs.read().await.get(&tunnel_id).cloned();
                        let control = reader_control.clone();
                        tokio::spawn(async move {
                            let (ok, message) = match spec {
                                None => (false, Some("unknown_tunnel".into())),
                                Some(spec) => probe_local_service(&spec).await,
                            };
                            let result = ControlMessage::ProbeResult {
                                probe_id,
                                ok,
                                message,
                            };
                            if let Ok(payload) = encode(&result) {
                                let _ = control
                                    .send(Message::Text(
                                        String::from_utf8_lossy(&payload).into_owned().into(),
                                    ))
                                    .await;
                            }
                        });
                    }
                    _ => {}
                },
                _ => {}
            }
        }
        reader_done_notify.notify_one();
    });

    let mut reconnect = false;
    loop {
        let heartbeat_secs = status.settings.read().await.heartbeat_secs;
        tokio::select! {
            _ = tokio::time::sleep(Duration::from_secs(heartbeat_secs)) => {}
            _ = reader_done.notified() => break,
            _ = settings_changed.notified() => {
                reconnect = true;
                break;
            }
        }
        let now = Instant::now();
        pending
            .write()
            .await
            .retain(|_, (at, _)| now.duration_since(*at) < Duration::from_secs(10));
        // After wake-from-sleep the TCP connection may be dead while the OS
        // keeps retransmitting; require a fresh pong or reconnect promptly.
        let pong_timeout_secs = status.settings.read().await.pong_timeout_secs;
        if last_pong.lock().unwrap().elapsed() > Duration::from_secs(pong_timeout_secs) {
            break;
        }
        let heartbeat = ControlMessage::Heartbeat {
            version: PROTOCOL_VERSION,
            latency_ms: 0,
        };
        if let Ok(payload) = encode(&heartbeat) {
            // The pong timeout still guards a dead connection.
            let _ = control_tx.try_send(Message::Text(
                String::from_utf8_lossy(&payload).into_owned().into(),
            ));
        }
        let _ = control_tx.try_send(Message::Ping(Vec::new().into()));
    }
    status.connections.write().await.clear();
    for task in data_tasks.lock().await.drain(..) {
        task.abort();
    }
    for (_, task) in bridge_tasks.lock().await.drain() {
        task.abort();
    }
    streams.write().await.clear();
    data_channels.write().await.clear();
    pending.write().await.clear();
    writer_task.abort();
    reader_task.abort();
    if reconnect {
        Ok(RunOutcome::ReconnectNow)
    } else {
        Ok(RunOutcome::Disconnected)
    }
}

/// Device-code enrollment: connects without a token, prints a one-time code
/// for the administrator, and waits for the server to issue a token. On
/// approval the token is persisted and the caller reconnects through the
/// normal `Register` path.
async fn run_enroll(config: &AgentConfig) -> Result<(), Box<dyn std::error::Error>> {
    let (socket, _) = connect_async(&config.server).await?;
    enable_tcp_keepalive(&socket);
    tracing::info!(server = %config.server, "connecting for device enrollment");
    let (mut sink, mut source) = socket.split();
    let credentials = load_credentials();
    let code = match credentials.get("ENROLL_CODE") {
        Some(code) if code.len() == ENROLL_CODE_LEN => code.clone(),
        _ => {
            let code = generate_enroll_code();
            let mut updates = HashMap::new();
            updates.insert("ENROLL_CODE".to_string(), code.clone());
            save_credentials(&updates)?;
            code
        }
    };
    println!("==============================================");
    println!("Device enrollment required.");
    println!("Enrollment code: {code}");
    println!("Give this one-time code to the administrator; it expires in 15 minutes.");
    println!("==============================================");
    tracing::info!(
        code,
        "device enrollment code; waiting for administrator approval"
    );
    let enroll = ControlMessage::Enroll {
        code: code.clone(),
        device_name: config.name.clone(),
    };
    sink.send(Message::Text(String::from_utf8(encode(&enroll)?)?.into()))
        .await?;
    loop {
        let Some(Ok(message)) = source.next().await else {
            return Err("enrollment socket closed before approval".into());
        };
        if let Message::Text(text) = message {
            if let Ok(ControlMessage::Enrolled { token, device_id }) = decode(text.as_bytes()) {
                tracing::info!(%device_id, "enrollment approved; persisting issued token");
                let mut updates = HashMap::new();
                updates.insert("TOKEN".to_string(), token);
                updates.insert("ENROLL_CODE".to_string(), String::new());
                save_credentials(&updates)?;
                println!("Enrollment approved. Reconnecting with the issued token.");
                return Ok(());
            }
            if let Ok(ControlMessage::Error {
                code: error_code,
                message,
            }) = decode(text.as_bytes())
            {
                tracing::warn!(code = %error_code, message, "enrollment rejected");
                // Consume the code so the next attempt shows a fresh one.
                let mut updates = HashMap::new();
                updates.insert("ENROLL_CODE".to_string(), String::new());
                let _ = save_credentials(&updates);
                println!("Enrollment {error_code}: {message}. A new code will be generated.");
                return Err("enrollment rejected".into());
            }
        }
    }
}

/// Sets an aggressive TCP keepalive so a half-open link (router reboot, NAT
/// table loss, WiFi handoff) is detected by the OS instead of waiting for the
/// pong timeout. Applied to the control socket and every data socket.
fn enable_tcp_keepalive(
    socket: &tokio_tungstenite::WebSocketStream<
        tokio_tungstenite::MaybeTlsStream<tokio::net::TcpStream>,
    >,
) {
    if let tokio_tungstenite::MaybeTlsStream::Plain(tcp) = socket.get_ref() {
        let socket_ref = socket2::SockRef::from(tcp);
        let _ = socket_ref
            .set_tcp_keepalive(&socket2::TcpKeepalive::new().with_time(Duration::from_secs(10)));
    }
}

/// One data WebSocket: binds to the control session with `DataBind`, waits for
/// `DataBound`, then relays binary frames until the socket drops. On failure it
/// retries with a short pause; the task is aborted when the control run ends.
async fn data_channel_task(
    config: AgentConfig,
    status: AgentStatus,
    streams: StreamMap,
    connections: ConnectionMap,
    control: mpsc::Sender<Message>,
    pending: PendingMap,
) {
    loop {
        match connect_async(&config.data_server).await {
            Ok((socket, _)) => {
                enable_tcp_keepalive(&socket);
                let (mut sink, mut source) = socket.split();
                let bind = ControlMessage::DataBind {
                    token: config.token.clone(),
                };
                let Ok(payload) = encode(&bind) else {
                    tokio::time::sleep(Duration::from_secs(1)).await;
                    continue;
                };
                if sink
                    .send(Message::Text(
                        String::from_utf8_lossy(&payload).into_owned().into(),
                    ))
                    .await
                    .is_err()
                {
                    tokio::time::sleep(Duration::from_secs(1)).await;
                    continue;
                }
                let bound = tokio::time::timeout(Duration::from_secs(5), async {
                    while let Some(Ok(message)) = source.next().await {
                        if let Message::Text(text) = message {
                            if let Ok(ControlMessage::DataBound { channel_id }) =
                                decode(text.as_bytes())
                            {
                                return Some(channel_id);
                            }
                        }
                    }
                    None
                })
                .await
                .ok()
                .flatten();
                let Some(channel_id) = bound else {
                    // The server may reject us while the control session is not
                    // ready yet; retry shortly.
                    tokio::time::sleep(Duration::from_secs(1)).await;
                    continue;
                };
                let (tx, mut rx) = mpsc::channel::<Message>(512);
                status
                    .data_channels
                    .write()
                    .await
                    .insert(channel_id, tx.clone());
                let writer = tokio::spawn(async move {
                    while let Some(message) = rx.recv().await {
                        if sink.send(message).await.is_err() {
                            break;
                        }
                    }
                });
                // Data channels carry no game traffic while the tunnel is
                // idle, so proxies (Nginx) and NAT tables would otherwise age
                // the WebSocket out and drop every stream on it. A periodic
                // heartbeat keeps the channel alive in both directions: the
                // server echoes it back over the same socket.
                let heartbeat_tx = tx.clone();
                let heartbeat_secs = config.heartbeat_secs;
                let keepalive = tokio::spawn(async move {
                    let mut ticker = tokio::time::interval(Duration::from_secs(heartbeat_secs));
                    ticker.tick().await; // skip the immediate first tick
                    loop {
                        ticker.tick().await;
                        let Ok(payload) = encode(&ControlMessage::Heartbeat {
                            version: PROTOCOL_VERSION,
                            latency_ms: 0,
                        }) else {
                            break;
                        };
                        let message =
                            Message::Text(String::from_utf8_lossy(&payload).into_owned().into());
                        if heartbeat_tx.try_send(message).is_err() && heartbeat_tx.is_closed() {
                            break;
                        }
                    }
                });
                let reader_streams = streams.clone();
                let reader_connections = connections.clone();
                let reader_control = control.clone();
                let reader_pending = pending.clone();
                while let Some(Ok(message)) = source.next().await {
                    if let Message::Binary(bytes) = message {
                        if let Ok((id, data)) = decode_stream_data(&bytes) {
                            route_agent_binary(
                                &reader_streams,
                                &reader_connections,
                                &reader_control,
                                &reader_pending,
                                id,
                                data,
                            )
                            .await;
                        }
                    }
                }
                writer.abort();
                keepalive.abort();
                status.data_channels.write().await.remove(&channel_id);
                tracing::warn!(channel_id, "data channel lost; reconnecting");
                tokio::time::sleep(Duration::from_secs(1)).await;
            }
            Err(error) => {
                tracing::warn!(%error, "data channel connect failed; retrying");
                tokio::time::sleep(Duration::from_secs(1)).await;
            }
        }
    }
}

/// Routes one binary frame arriving on a data socket to its stream. TCP
/// streams are closed when saturated; UDP datagrams are dropped instead.
async fn route_agent_binary(
    streams: &StreamMap,
    connections: &ConnectionMap,
    control: &mpsc::Sender<Message>,
    pending: &PendingMap,
    id: u128,
    data: &[u8],
) {
    let tx = {
        let map = streams.read().await;
        map.get(&id).cloned()
    };
    let Some(tx) = tx else {
        // `StreamOpen` travels on the control socket while data frames arrive
        // on data sockets; the first frames can beat the registration. Buffer
        // them briefly so the StreamOpen handler can flush them once the
        // stream exists, instead of silently dropping the first bytes.
        let mut guard = pending.write().await;
        let entry = guard
            .entry(id)
            .or_insert_with(|| (Instant::now(), Vec::new()));
        if entry.1.len() < PENDING_STREAM_FRAMES {
            entry.1.push(data.to_vec());
        }
        return;
    };
    if tx.try_send(data.to_vec()).is_ok() {
        return;
    }
    let is_udp = connections
        .read()
        .await
        .get(&id)
        .map(|connection| {
            let kind = &connection.kind;
            kind == "udp"
        })
        .unwrap_or(false);
    if is_udp {
        // UDP tolerates loss; drop the datagram and keep the session alive.
        return;
    }
    // Never block a data channel on one saturated TCP stream; close it so the
    // client can reconnect.
    drop_stream(&streams, &connections, id, "local_saturated").await;
    send_close(control, id.to_string(), Some("local_saturated".into()));
}

/// Verifies the agent can reach the tunnel's local service. TCP/HTTP attempt a
/// real connect; UDP only proves the local socket can bind/connect because UDP
/// has no connection semantics and the service protocol is unknown.
async fn probe_local_service(spec: &TunnelSpec) -> (bool, Option<String>) {
    let target = format!("{}:{}", spec.local_host, spec.local_port);
    match &spec.kind {
        TunnelKind::Udp => match UdpSocket::bind("0.0.0.0:0").await {
            Ok(socket) => {
                match tokio::time::timeout(Duration::from_secs(5), socket.connect(target)).await {
                    Ok(Ok(())) => (
                        true,
                        Some("udp socket ready; real reachability requires a live client".into()),
                    ),
                    Ok(Err(error)) => (false, Some(format!("udp local connect failed: {error}"))),
                    Err(_) => (false, Some("udp local connect timed out".into())),
                }
            }
            Err(error) => (false, Some(format!("udp bind failed: {error}"))),
        },
        _ => {
            match tokio::time::timeout(Duration::from_secs(5), TcpStream::connect(&target)).await {
                Ok(Ok(_)) => (true, Some("local tcp service reachable".into())),
                Ok(Err(error)) => (false, Some(format!("local tcp connect failed: {error}"))),
                Err(_) => (false, Some("local tcp connect timed out".into())),
            }
        }
    }
}

async fn bridge_local(
    id: u128,
    spec: TunnelSpec,
    mut rx: mpsc::Receiver<Vec<u8>>,
    data: mpsc::Sender<Message>,
    control: mpsc::Sender<Message>,
    streams: StreamMap,
    connections: ConnectionMap,
    limiter: BandwidthLimiter,
) {
    let Ok(socket) = TcpStream::connect(format!("{}:{}", spec.local_host, spec.local_port)).await
    else {
        drop_stream(&streams, &connections, id, "local_connect_failed").await;
        send_close(
            &control,
            id.to_string(),
            Some("local_connect_failed".into()),
        );
        return;
    };
    let (mut reader, mut writer) = socket.into_split();
    let write_task = tokio::spawn(async move {
        while let Some(data) = rx.recv().await {
            if writer.write_all(&data).await.is_err() {
                break;
            }
        }
    });
    let mut buffer = [0_u8; 16 * 1024];
    loop {
        match reader.read(&mut buffer).await {
            Ok(0) | Err(_) => break,
            Ok(size) => {
                // Throttle at the source so a fast local service can never
                // saturate the shared control WebSocket.
                limiter.acquire(size).await;
                let Ok(frame) = encode_stream_data(id, &buffer[..size]) else {
                    break;
                };
                // TCP must not drop bytes, so queue on the data channel rather
                // than closing the stream; control messages still jump ahead.
                if data.send(Message::Binary(frame.into())).await.is_err() {
                    break;
                }
            }
        }
    }
    drop_stream(&streams, &connections, id, "ended").await;
    write_task.abort();
    send_close(&control, id.to_string(), None);
}

async fn bridge_local_udp(
    id: u128,
    spec: TunnelSpec,
    mut rx: mpsc::Receiver<Vec<u8>>,
    data: mpsc::Sender<Message>,
    control: mpsc::Sender<Message>,
    streams: StreamMap,
    connections: ConnectionMap,
    limiter: BandwidthLimiter,
) {
    let Ok(socket) = UdpSocket::bind("0.0.0.0:0").await else {
        drop_stream(&streams, &connections, id, "local_bind_failed").await;
        send_close(&control, id.to_string(), Some("local_bind_failed".into()));
        return;
    };
    if socket
        .connect(format!("{}:{}", spec.local_host, spec.local_port))
        .await
        .is_err()
    {
        drop_stream(&streams, &connections, id, "local_connect_failed").await;
        send_close(
            &control,
            id.to_string(),
            Some("local_connect_failed".into()),
        );
        return;
    }
    let socket = Arc::new(socket);
    let writer_socket = socket.clone();
    let write_task = tokio::spawn(async move {
        while let Some(data) = rx.recv().await {
            if writer_socket.send(&data).await.is_err() {
                break;
            }
        }
    });
    let mut buffer = [0_u8; 65536];
    loop {
        match socket.recv(&mut buffer).await {
            // A zero-length datagram is a valid UDP packet; relay it instead
            // of treating it as EOF (which would silently kill the session).
            Err(_) => break,
            Ok(size) => {
                limiter.acquire(size).await;
                let Ok(frame) = encode_stream_data(id, &buffer[..size]) else {
                    break;
                };
                if data.try_send(Message::Binary(frame.into())).is_err() {
                    // UDP tolerates loss; drop the datagram rather than stall
                    // the data channel.
                    continue;
                }
            }
        }
    }
    drop_stream(&streams, &connections, id, "ended").await;
    write_task.abort();
    send_close(&control, id.to_string(), None);
}

async fn drop_stream(streams: &StreamMap, connections: &ConnectionMap, id: u128, reason: &str) {
    streams.write().await.remove(&id);
    connections.write().await.remove(&id);
    tracing::info!(stream_id = %id, reason, "stream closed");
}

fn send_close(control: &mpsc::Sender<Message>, stream_id: String, reason: Option<String>) {
    let close = ControlMessage::StreamClose { stream_id, reason };
    if let Ok(payload) = encode(&close) {
        let _ = control.try_send(Message::Text(
            String::from_utf8_lossy(&payload).into_owned().into(),
        ));
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use tokio::net::TcpListener;

    #[tokio::test]
    async fn agent_limiter_paces_outbound_at_cap() {
        let limiter = BandwidthLimiter::new(1);
        let started = Instant::now();
        let mut sent = 0usize;
        // Four seconds worth of budget: the first second is the burst, the
        // remaining three seconds must be paced by the token bucket.
        while sent < 500_000 {
            limiter.acquire(1_250).await;
            sent += 1_250;
        }
        let elapsed = started.elapsed().as_secs_f64();
        assert!(elapsed >= 2.5 && elapsed < 6.0, "elapsed {elapsed}");
    }

    #[tokio::test]
    async fn agent_limiter_disabled_passes_through() {
        let limiter = BandwidthLimiter::new(0);
        let started = Instant::now();
        for _ in 0..100 {
            limiter.acquire(64 * 1024).await;
        }
        assert!(started.elapsed().as_millis() < 500);
    }

    #[tokio::test]
    async fn udp_bridge_relays_datagrams_both_ways() {
        let echo = UdpSocket::bind("127.0.0.1:0").await.unwrap();
        let echo_addr = echo.local_addr().unwrap();
        let echo_task = tokio::spawn(async move {
            let mut buf = [0_u8; 4096];
            let (size, peer) = echo.recv_from(&mut buf).await.unwrap();
            echo.send_to(&buf[..size], peer).await.unwrap();
        });

        let spec = TunnelSpec {
            id: "tunnel-udp".into(),
            name: "udp test".into(),
            kind: TunnelKind::Udp,
            public_port: 19000,
            local_host: "127.0.0.1".into(),
            local_port: echo_addr.port(),
            enabled: true,
            max_connections: 10,
        };
        let (data_tx, mut data_rx) = mpsc::channel::<Message>(64);
        let (control_tx, _control_rx) = mpsc::channel::<Message>(64);
        let streams: StreamMap = Arc::new(RwLock::new(HashMap::new()));
        let connections: ConnectionMap = Arc::new(RwLock::new(HashMap::new()));
        let (tx, rx) = mpsc::channel::<Vec<u8>>(128);
        // The StreamOpen handler registers the stream before spawning the bridge.
        streams.write().await.insert(42, tx.clone());
        let bridge = tokio::spawn(bridge_local_udp(
            42,
            spec,
            rx,
            data_tx,
            control_tx,
            streams.clone(),
            connections.clone(),
            BandwidthLimiter::new(0),
        ));

        tx.send(b"hello-udp".to_vec()).await.unwrap();

        let message = tokio::time::timeout(Duration::from_secs(2), data_rx.recv())
            .await
            .expect("timeout waiting for echoed datagram")
            .expect("channel closed");
        let Message::Binary(bytes) = message else {
            panic!("expected binary frame with echoed datagram");
        };
        let (id, data) = decode_stream_data(&bytes).unwrap();
        assert_eq!(id, 42);
        assert_eq!(data, b"hello-udp");

        echo_task.abort();
        bridge.abort();
    }

    #[tokio::test]
    async fn udp_bridge_relays_zero_length_datagram() {
        let echo = UdpSocket::bind("127.0.0.1:0").await.unwrap();
        let echo_addr = echo.local_addr().unwrap();
        let echo_task = tokio::spawn(async move {
            let mut buf = [0_u8; 4096];
            loop {
                let Ok((size, peer)) = echo.recv_from(&mut buf).await else {
                    break;
                };
                if echo.send_to(&buf[..size], peer).await.is_err() {
                    break;
                }
            }
        });

        let spec = TunnelSpec {
            id: "tunnel-udp-empty".into(),
            name: "udp empty test".into(),
            kind: TunnelKind::Udp,
            public_port: 19001,
            local_host: "127.0.0.1".into(),
            local_port: echo_addr.port(),
            enabled: true,
            max_connections: 10,
        };
        let (data_tx, mut data_rx) = mpsc::channel::<Message>(64);
        let (control_tx, _control_rx) = mpsc::channel::<Message>(64);
        let streams: StreamMap = Arc::new(RwLock::new(HashMap::new()));
        let connections: ConnectionMap = Arc::new(RwLock::new(HashMap::new()));
        let (tx, rx) = mpsc::channel::<Vec<u8>>(128);
        streams.write().await.insert(43, tx.clone());
        let bridge = tokio::spawn(bridge_local_udp(
            43,
            spec,
            rx,
            data_tx,
            control_tx,
            streams.clone(),
            connections.clone(),
            BandwidthLimiter::new(0),
        ));

        // An empty datagram is legal; it must be relayed, not treated as EOF.
        tx.send(Vec::new()).await.unwrap();
        let message = tokio::time::timeout(Duration::from_secs(2), data_rx.recv())
            .await
            .expect("timeout waiting for empty datagram")
            .expect("channel closed");
        let Message::Binary(bytes) = message else {
            panic!("expected binary frame");
        };
        let (id, data) = decode_stream_data(&bytes).unwrap();
        assert_eq!(id, 43);
        assert!(
            data.is_empty(),
            "zero-length datagram must be relayed intact"
        );

        // The session must still be alive after the empty datagram.
        tx.send(b"still-alive".to_vec()).await.unwrap();
        let message = tokio::time::timeout(Duration::from_secs(2), data_rx.recv())
            .await
            .expect("timeout waiting for second datagram")
            .expect("channel closed");
        let Message::Binary(bytes) = message else {
            panic!("expected binary frame");
        };
        let (_, data) = decode_stream_data(&bytes).unwrap();
        assert_eq!(data, b"still-alive");

        echo_task.abort();
        bridge.abort();
    }

    #[tokio::test]
    async fn stream_close_aborts_idle_bridge() {
        let listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
        let addr = listener.local_addr().unwrap();
        let accept_task = tokio::spawn(async move {
            // Accept and hold the connection open without ever writing, so the
            // bridge read loop would block forever without the abort.
            let _ = listener.accept().await;
        });
        let spec = TunnelSpec {
            id: "tunnel-tcp-close".into(),
            name: "tcp close test".into(),
            kind: TunnelKind::Tcp,
            public_port: 18002,
            local_host: "127.0.0.1".into(),
            local_port: addr.port(),
            enabled: true,
            max_connections: 10,
        };
        let (data_tx, _data_rx) = mpsc::channel::<Message>(64);
        let (control_tx, _control_rx) = mpsc::channel::<Message>(64);
        let streams: StreamMap = Arc::new(RwLock::new(HashMap::new()));
        let connections: ConnectionMap = Arc::new(RwLock::new(HashMap::new()));
        let (tx, rx) = mpsc::channel::<Vec<u8>>(128);
        streams.write().await.insert(7, tx.clone());
        let bridge = tokio::spawn(bridge_local(
            7,
            spec,
            rx,
            data_tx,
            control_tx,
            streams.clone(),
            connections.clone(),
            BandwidthLimiter::new(0),
        ));
        tokio::time::sleep(Duration::from_millis(200)).await;
        // Simulate the StreamClose handler: unregister the stream and abort
        // the bridge so it cannot linger on an idle local connection.
        streams.write().await.remove(&7);
        bridge.abort();
        assert!(
            tokio::time::timeout(Duration::from_secs(1), bridge)
                .await
                .is_ok(),
            "bridge task must terminate after StreamClose abort"
        );
        accept_task.abort();
    }

    #[test]
    fn reconnect_delay_grows_and_stays_bounded() {
        let min = 1;
        let max = 10;
        assert_eq!(reconnect_delay(0, min, max, 1.0), Duration::from_secs(1));
        assert_eq!(reconnect_delay(4, min, max, 1.0), Duration::from_secs(10));
        let base = reconnect_delay(2, min, max, 1.0);
        let low = reconnect_delay(2, min, max, 0.7);
        let high = reconnect_delay(2, min, max, 1.3);
        assert!(low < base && base < high);
        let extreme = reconnect_delay(10, min, max, 1.3);
        assert!(extreme.as_secs_f64() <= max as f64 * 1.3 + 1e-9);
    }

    #[test]
    fn enroll_code_uses_alphabet_and_length() {
        for _ in 0..20 {
            let code = generate_enroll_code();
            assert_eq!(code.len(), ENROLL_CODE_LEN);
            assert!(
                code.bytes()
                    .all(|byte| ENROLL_CODE_ALPHABET.contains(&byte))
            );
        }
    }

    #[test]
    fn pick_num_prefers_first_valid_source() {
        let credentials = HashMap::from([("DATA_CHANNELS".to_string(), "6".to_string())]);
        let file = HashMap::from([("DATA_CHANNELS".to_string(), "3".to_string())]);
        assert_eq!(
            pick_num(&["DATA_CHANNELS"], &[&credentials, &file], 2, 1, 8),
            6
        );
        // Out-of-range values are skipped in favor of the next source/default.
        let bad = HashMap::from([("DATA_CHANNELS".to_string(), "99".to_string())]);
        assert_eq!(pick_num(&["DATA_CHANNELS"], &[&bad, &file], 2, 1, 8), 3);
        assert_eq!(pick_num(&["MISSING"], &[&bad, &file], 2, 1, 8), 2);
    }

    #[test]
    fn credentials_round_trip_clears_empty_keys() {
        let dir = std::env::temp_dir().join(format!("tunnel-agent-test-{}", uuid::Uuid::new_v4()));
        std::fs::create_dir_all(&dir).unwrap();
        // Test-only env mutation; tests are single-threaded here.
        unsafe { std::env::set_var("TUNNEL_CREDENTIALS_FILE", dir.join("credentials")) };
        let mut first = HashMap::new();
        first.insert("TOKEN".to_string(), "abc".to_string());
        first.insert("ENROLL_CODE".to_string(), "XYZ12345".to_string());
        save_credentials(&first).unwrap();
        assert_eq!(
            load_credentials().get("TOKEN").map(String::as_str),
            Some("abc")
        );
        let mut second = HashMap::new();
        second.insert("ENROLL_CODE".to_string(), String::new());
        save_credentials(&second).unwrap();
        let after = load_credentials();
        assert!(after.get("ENROLL_CODE").is_none());
        assert_eq!(after.get("TOKEN").map(String::as_str), Some("abc"));
        let _ = std::fs::remove_dir_all(&dir);
        unsafe { std::env::remove_var("TUNNEL_CREDENTIALS_FILE") };
    }
}
