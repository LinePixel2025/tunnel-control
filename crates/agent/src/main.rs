use futures_util::{SinkExt, StreamExt};
use rand::Rng;
use serde::{Deserialize, Serialize};
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
        atomic::{AtomicBool, AtomicU64, Ordering},
    },
    time::{Duration, Instant, SystemTime},
};
use tokio::{
    io::{AsyncReadExt, AsyncWriteExt},
    net::{TcpStream, UdpSocket},
    sync::{Mutex, Notify, RwLock, mpsc},
};
use tokio_tungstenite::{connect_async, tungstenite::Message};
use tracing_subscriber::prelude::*;
use tracing_subscriber::{EnvFilter, reload};
use tunnel_protocol::{
    AgentSettings, ControlMessage, MAX_FRAME_BYTES, PROTOCOL_VERSION, TCP_CHUNK_SIZE, TunnelKind,
    TunnelSpec, decode, decode_stream_data, encode, encode_stream_data,
};
use url::Url;

#[cfg(windows)]
use std::os::windows::process::CommandExt;

/// Enrollment pairing code alphabet and length; the same constants live in the
/// server so both sides agree on what a valid code looks like.
const ENROLL_CODE_LEN: usize = 8;
const ENROLL_CODE_ALPHABET: &[u8] = b"23456789ABCDEFGHJKMNPQRSTUVWXYZ";

/// Preset server offered on first start in the client console.
const OFFICIAL_SERVER_URL: &str = "ws://123.207.8.77:18080/control";

/// Runtime hook for the tracing filter so `SettingsSync` can change the log
/// level without restarting the process. The concrete reload handle is hidden
/// inside the closure to avoid naming the full subscriber type.
static LOG_FILTER: OnceLock<Arc<dyn Fn(&str) + Send + Sync>> = OnceLock::new();

/// One agent-side TCP stream: the bounded local queue used by data-socket
/// frames, plus its share of the shared data-channel writer queue. The slot
/// mirrors the server's `StreamSlot` so a bulk upload cannot head-of-line
/// block other streams on the same channel.
struct StreamEntry {
    tx: mpsc::Sender<Vec<u8>>,
    slot: Arc<Mutex<StreamSlot>>,
}

type StreamMap = Arc<RwLock<HashMap<u128, StreamEntry>>>;
type ConnectionMap = Arc<RwLock<HashMap<u128, ConnectionInfo>>>;
type DataSenderMap = Arc<RwLock<HashMap<u16, mpsc::Sender<Message>>>>;
type TaskMap = Arc<tokio::sync::Mutex<HashMap<u128, tokio::task::JoinHandle<()>>>>;
/// Pending pre-`StreamOpen` frames: first-arrival time, frames in arrival
/// order, and the total buffered byte count.
type PendingMap = Arc<RwLock<HashMap<u128, (Instant, Vec<Vec<u8>>, usize)>>>;

/// Per-channel traffic counters shared between the data-channel task and the
/// IPC snapshot handler. They live for the whole agent process so the
/// `traffic` console command reports bytes accumulated across reconnects,
/// not just the current socket session.
#[derive(Default)]
struct ChannelCounters {
    up_bytes: AtomicU64,
    down_bytes: AtomicU64,
    connected: AtomicBool,
}

impl ChannelCounters {
    fn snapshot(&self) -> (u64, u64, bool) {
        (
            self.up_bytes.load(Ordering::Relaxed),
            self.down_bytes.load(Ordering::Relaxed),
            self.connected.load(Ordering::Relaxed),
        )
    }
}

/// Process-wide map of per-channel counters, keyed by the server-assigned
/// data channel id (1-based). Cloning shares the same underlying counters.
#[derive(Clone, Default)]
struct TrafficStats {
    channels: Arc<RwLock<HashMap<u16, Arc<ChannelCounters>>>>,
}

/// Local-only IPC messages exchanged between the client console and the
/// running agent process over a named pipe. Not part of the server protocol.
#[derive(Debug, Clone, Serialize, Deserialize)]
struct IpcRequest {
    cmd: String,
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
struct IpcChannelStat {
    channel_id: u16,
    up_bytes: u64,
    down_bytes: u64,
    connected: bool,
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
struct IpcTrafficTotals {
    up_bytes: u64,
    down_bytes: u64,
    total_bytes: u64,
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
struct IpcSnapshot {
    settings: AgentSettings,
    settings_synced_at: Option<u64>,
    channels: Vec<IpcChannelStat>,
    totals: IpcTrafficTotals,
}

/// Byte budget for frames buffered before a stream's `StreamOpen` arrives
/// (control and data sockets have no ordering guarantee). Four protocol
/// frames cover the realistic cross-socket race; if traffic keeps arriving
/// the buffer grows with a warning instead of dropping TCP bytes, up to the
/// hard limit below; the 10s pending expiry reclaims entries whose
/// `StreamOpen` never arrives.
const PENDING_STREAM_BYTES: usize = 4 * MAX_FRAME_BYTES;
/// Hard ceiling for the pre-`StreamOpen` buffer. Above this the stream is
/// never going to register normally, so further frames are dropped with an
/// error log instead of letting one pathological stream consume unbounded
/// memory inside the 10s expiry window.
const PENDING_STREAM_HARD_BYTES: usize = 64 * 1024 * 1024;

/// Frames buffered per TCP stream before local backpressure applies; 64 x
/// 64KiB keeps the worst-case per-stream queue at 4MiB.
const STREAM_QUEUE_FRAMES: usize = 64;

/// Frames buffered per data channel; 128 x 64KiB keeps the worst-case shared
/// queue at 8MiB, matching the old 512 x 16KiB budget.
const DATA_CHANNEL_QUEUE_FRAMES: usize = 128;

/// Max frames one stream may have waiting in its data channel's shared writer
/// queue. Mirrors the server's `STREAM_CHANNEL_QUOTA` so one upload stream
/// cannot head-of-line block the other streams on the same channel.
const STREAM_CHANNEL_QUOTA: usize = 16;

/// One stream's share of its data channel's shared writer queue. `outstanding`
/// counts frames queued but not yet forwarded by the channel writer; when it
/// reaches `STREAM_CHANNEL_QUOTA` the bridge waits so a single bulk upload
/// stream cannot head-of-line block the other streams on the channel.
struct StreamSlot {
    outstanding: usize,
    notify: Arc<Notify>,
}

impl Default for StreamSlot {
    fn default() -> Self {
        Self {
            outstanding: 0,
            notify: Arc::new(Notify::new()),
        }
    }
}

/// Upper bound on how long routing waits for one TCP frame to enter a
/// stream's bounded queue before closing the stream. Waiting (instead of
/// dropping or closing) turns queue pressure into TCP backpressure; the cap
/// prevents a wedged local service from stalling the data channel forever.
const TCP_SEND_TIMEOUT: Duration = Duration::from_secs(30);

/// Data-channel reconnect backoff: start at 1s, double per failed attempt,
/// and cap at 60s so a down server does not produce a reconnect storm. This
/// is independent from the control-channel backoff configured by the server.
const DATA_CHANNEL_RETRY_MIN: Duration = Duration::from_secs(1);
const DATA_CHANNEL_RETRY_MAX: Duration = Duration::from_secs(60);

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
    settings_synced_at: Arc<std::sync::Mutex<Option<u64>>>,
    traffic: TrafficStats,
}

impl AgentStatus {
    fn new(config: &AgentConfig) -> Self {
        Self {
            specs: Arc::new(RwLock::new(HashMap::new())),
            connections: Arc::new(RwLock::new(HashMap::new())),
            data_channels: Arc::new(RwLock::new(HashMap::new())),
            bandwidth: BandwidthLimiter::default(),
            settings: Arc::new(RwLock::new(config.to_agent_settings())),
            settings_synced_at: Arc::new(std::sync::Mutex::new(None)),
            traffic: TrafficStats::default(),
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
            .filter(|value| !value.trim().is_empty())
            .or_else(|| {
                credentials
                    .get("SERVER_URL")
                    .cloned()
                    .filter(|value| !value.trim().is_empty())
            })
            .or_else(|| file.get("TUNNEL_SERVER_URL").cloned())
            .unwrap_or_else(|| "ws://127.0.0.1:18080/control".into());
        let token = env::var("TUNNEL_TOKEN")
            .ok()
            .filter(|value| !value.trim().is_empty())
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

/// Backoff before the next data-channel reconnect attempt: exponential
/// growth from `DATA_CHANNEL_RETRY_MIN`, capped at `DATA_CHANNEL_RETRY_MAX`,
/// with random 0.7..=1.3 jitter.
fn data_channel_backoff(attempt: u32) -> Duration {
    let growth = 2_f64.powi(attempt.min(5) as i32);
    let base =
        (DATA_CHANNEL_RETRY_MIN.as_secs_f64() * growth).min(DATA_CHANNEL_RETRY_MAX.as_secs_f64());
    let fraction = rand::thread_rng().gen_range(0.7..=1.3);
    Duration::from_secs_f64((base * fraction).max(0.1))
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
use tokio::net::windows::named_pipe::{ClientOptions, NamedPipeServer, ServerOptions};

#[cfg(windows)]
define_windows_service!(ffi_service_main, service_main);

/// Quotes one Windows command-line argument the way CommandLineToArgvW parses
/// it: wrapped in double quotes when it contains spaces or quotes, with
/// embedded quotes escaped by backslashes.
fn quote_win_arg(arg: &str) -> String {
    if arg.is_empty() {
        return "\"\"".to_string();
    }
    if !arg
        .bytes()
        .any(|byte| byte.is_ascii_whitespace() || byte == b'"')
    {
        return arg.to_string();
    }
    let mut out = String::from("\"");
    for byte in arg.bytes() {
        if byte == b'"' {
            out.push('\\');
        }
        out.push(byte as char);
    }
    out.push('"');
    out
}

#[cfg(windows)]
mod elevation {
    use super::quote_win_arg;
    use windows_sys::Win32::{
        Foundation::{CloseHandle, HANDLE},
        Security::{GetTokenInformation, TOKEN_ELEVATION, TOKEN_QUERY, TokenElevation},
        System::Threading::{GetCurrentProcess, OpenProcessToken},
        UI::Shell::ShellExecuteW,
    };

    pub fn is_elevated() -> bool {
        unsafe {
            let mut token: HANDLE = 0;
            if OpenProcessToken(GetCurrentProcess(), TOKEN_QUERY, &mut token) == 0 {
                return false;
            }
            let mut elevation = TOKEN_ELEVATION { TokenIsElevated: 0 };
            let mut size = 0u32;
            let ok = GetTokenInformation(
                token,
                TokenElevation,
                &mut elevation as *mut _ as *mut core::ffi::c_void,
                core::mem::size_of::<TOKEN_ELEVATION>() as u32,
                &mut size,
            );
            CloseHandle(token);
            ok != 0 && elevation.TokenIsElevated != 0
        }
    }

    /// Relaunches the current executable with the UAC "run as administrator"
    /// verb, forwarding the original arguments. Returns true when the elevated
    /// process was started (the caller should exit).
    pub fn relaunch_elevated(arguments: &[String]) -> bool {
        let Some(exe) = std::env::current_exe().ok() else {
            return false;
        };
        let exe_wide: Vec<u16> = exe
            .to_string_lossy()
            .encode_utf16()
            .chain(Some(0))
            .collect();
        let parameters = arguments
            .iter()
            .map(|argument| quote_win_arg(argument))
            .collect::<Vec<_>>()
            .join(" ");
        let parameters_wide: Vec<u16> = parameters.encode_utf16().chain(Some(0)).collect();
        let runas: Vec<u16> = "runas".encode_utf16().chain(Some(0)).collect();
        let result = unsafe {
            ShellExecuteW(
                0, // HWND (isize): no parent window
                runas.as_ptr(),
                exe_wide.as_ptr(),
                parameters_wide.as_ptr(),
                std::ptr::null(),
                1, // SW_SHOWNORMAL
            )
        };
        (result as isize) > 32
    }
}

/// Returns true when the process should stop because an elevated relaunch was
/// started. Console, install, uninstall, and reset all require elevation;
/// service/agent workers and the read-only logs command never prompt. Set
/// TUNNEL_SKIP_ELEVATION=1 to bypass (useful for scripting/testing).
fn maybe_self_elevate(arguments: &[String]) -> bool {
    #[cfg(windows)]
    {
        if std::env::var_os("TUNNEL_SKIP_ELEVATION").is_some() {
            return false;
        }
        if arguments
            .iter()
            .any(|argument| argument == "--service" || argument == "--agent")
        {
            return false;
        }
        if matches!(
            arguments.get(1).map(String::as_str),
            Some("logs") | Some("settings") | Some("traffic")
        ) {
            return false;
        }
        if elevation::is_elevated() {
            return false;
        }
        println!("当前不是管理员，正在请求管理员权限…");
        if elevation::relaunch_elevated(arguments) {
            println!("已请求管理员权限，请在弹出的 UAC 窗口中确认；本窗口即将退出。");
            true
        } else {
            println!("自动提权失败（可能已被取消）。继续以当前权限运行，部分操作可能失败。");
            false
        }
    }
    #[cfg(not(windows))]
    {
        let _ = arguments;
        false
    }
}

fn main() {
    let arguments: Vec<String> = env::args().collect();
    if arguments
        .iter()
        .any(|argument| argument == "--version" || argument == "-V")
    {
        println!("tunnel-agent {}", env!("CARGO_PKG_VERSION"));
        return;
    }
    if maybe_self_elevate(&arguments) {
        return;
    }
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
    if arguments.get(1).map(String::as_str) == Some("reset") {
        setup_logging(false);
        if let Err(error) = reset_local_data() {
            eprintln!("Reset failed: {error}");
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
    if arguments.get(1).map(String::as_str) == Some("settings") {
        setup_logging(false);
        console_settings();
        return;
    }
    if arguments.get(1).map(String::as_str) == Some("traffic") {
        setup_logging(false);
        console_traffic();
        return;
    }
    if arguments.iter().any(|argument| argument == "--agent") {
        setup_logging(true);
        run_agent_forever();
        return;
    }
    run_console();
}

/// Per-user state for the client console. The console points the credential
/// and log helpers at this directory so a non-elevated user can run it
/// without touching the Windows service files under %PROGRAMDATA%.
fn console_state_dir() -> PathBuf {
    let root = env::var_os("LOCALAPPDATA").unwrap_or_else(|| env::temp_dir().into_os_string());
    PathBuf::from(root).join("TunnelControl")
}

fn console_credentials_file() -> PathBuf {
    console_state_dir().join("credentials")
}

fn console_log_dir() -> PathBuf {
    console_state_dir().join("logs")
}

fn console_pid_file() -> PathBuf {
    console_state_dir().join("agent.pid")
}

fn validate_server_url(url: &str) -> bool {
    url.starts_with("ws://") || url.starts_with("wss://")
}

/// Decides whether a pushed SettingsSync requires a reconnect. An empty
/// server_url means "not configured" and must never trigger a reconnect or
/// replace the local bootstrap address; a changed data_channels count always
/// requires reopening the data channels.
fn settings_reconnect_decision(current: &AgentSettings, incoming: &AgentSettings) -> bool {
    let server_url_changed =
        !incoming.server_url.is_empty() && incoming.server_url != current.server_url;
    server_url_changed || incoming.data_channels != current.data_channels
}

fn read_prompt(label: &str) -> Option<String> {
    print!("{label}> ");
    let _ = io::stdout().flush();
    let mut line = String::new();
    match io::stdin().read_line(&mut line) {
        Ok(0) | Err(_) => None,
        Ok(_) => Some(line.trim().to_string()),
    }
}

fn parse_pid_file(content: &str) -> Option<u32> {
    let value = content.trim();
    if value.is_empty() || !value.bytes().all(|byte| byte.is_ascii_digit()) {
        return None;
    }
    value.parse().ok()
}

fn read_console_pid() -> Option<u32> {
    fs::read_to_string(console_pid_file())
        .ok()
        .and_then(|content| parse_pid_file(&content))
}

fn write_console_pid(pid: u32) -> io::Result<()> {
    if let Some(parent) = console_pid_file().parent() {
        fs::create_dir_all(parent)?;
    }
    fs::write(console_pid_file(), pid.to_string())
}

/// Windows PowerShell 5.1 writes UTF-16LE to a redirected stdout, so every
/// ASCII character is followed by a NUL byte. Strip those NULs before text
/// matching so the same check works with Windows PowerShell and PowerShell 7.
fn ps_stdout_contains_bytes(stdout: &[u8], needle: &str) -> bool {
    String::from_utf8_lossy(stdout)
        .replace('\0', "")
        .contains(needle)
}

fn process_is_running(pid: u32) -> bool {
    let output = Command::new("powershell")
        .args([
            "-NoProfile",
            "-Command",
            &format!("(Get-Process -Id {pid} -ErrorAction SilentlyContinue).ProcessName"),
        ])
        .output();
    output
        .ok()
        .map(|output| ps_stdout_contains_bytes(&output.stdout, "tunnel-agent"))
        .unwrap_or(false)
}

#[cfg(not(windows))]
fn process_is_running(_pid: u32) -> bool {
    false
}

fn stop_process(pid: u32) {
    let _ = Command::new("powershell")
        .args([
            "-NoProfile",
            "-Command",
            &format!("Stop-Process -Id {pid} -Force"),
        ])
        .status();
}

fn service_is_running() -> bool {
    #[cfg(windows)]
    {
        let output = Command::new("powershell")
            .args([
                "-NoProfile",
                "-Command",
                "(Get-Service TunnelAgent -ErrorAction SilentlyContinue).Status -eq 'Running'",
            ])
            .output();
        return output
            .ok()
            .map(|output| ps_stdout_contains_bytes(&output.stdout, "True"))
            .unwrap_or(false);
    }
    #[cfg(not(windows))]
    false
}

/// First-run server selection: the operator picks the preset LineWeb server
/// or types a custom ws:// / wss:// address. The choice is persisted in the
/// per-user credentials file so later starts skip the prompt.
fn ensure_server_url() -> Option<String> {
    if let Some(url) = load_credentials().get("SERVER_URL").cloned() {
        return Some(url);
    }
    loop {
        println!();
        println!("首次启动：请选择服务器");
        println!("  1. LineWeb 官方 ({OFFICIAL_SERVER_URL})");
        println!("  2. 自定义服务器地址");
        let Some(choice) = read_prompt("选择 (1/2)") else {
            return None;
        };
        match choice.as_str() {
            "1" => {
                let _ = save_credentials(&HashMap::from([(
                    "SERVER_URL".to_string(),
                    OFFICIAL_SERVER_URL.to_string(),
                )]));
                println!("已选择 LineWeb 官方服务器。");
                return Some(OFFICIAL_SERVER_URL.to_string());
            }
            "2" => loop {
                let Some(url) = read_prompt("服务器地址 (ws:// 或 wss:// 开头)") else {
                    return None;
                };
                if validate_server_url(&url) {
                    let _ =
                        save_credentials(&HashMap::from([("SERVER_URL".to_string(), url.clone())]));
                    return Some(url);
                }
                println!("地址必须以 ws:// 或 wss:// 开头，请重新输入。");
            },
            _ => println!("请输入 1 或 2。"),
        }
    }
}

/// Returns the enrollment code the worker will present, generating and
/// persisting a fresh one when needed. The console prints it so the operator
/// sees it immediately instead of hunting through logs.
fn ensure_enrollment_code() -> String {
    let credentials = load_credentials();
    if let Some(code) = credentials.get("ENROLL_CODE") {
        if code.len() == ENROLL_CODE_LEN {
            return code.clone();
        }
    }
    let code = generate_enroll_code();
    let _ = save_credentials(&HashMap::from([("ENROLL_CODE".to_string(), code.clone())]));
    code
}

#[cfg(windows)]
fn start_agent_process() -> Option<u32> {
    if let Some(pid) = read_console_pid() {
        if process_is_running(pid) {
            println!("Agent is already running (PID {pid}).");
            return None;
        }
    }
    if service_is_running() {
        println!("WARNING: the TunnelAgent Windows service is running.");
        println!("Console mode and service mode would fight over the same device session.");
        println!(
            "Stop it first with:  sc.exe stop TunnelAgent   (or: tunnel-agent.exe --uninstall)"
        );
        return None;
    }
    let _server = ensure_server_url()?;
    // Env-var bootstrap values may be stale (legacy machine-level installs);
    // the worker must use only the per-user credentials the console manages.
    let pending_enrollment = load_credentials().get("TOKEN").is_none();
    let enrollment_code = pending_enrollment.then(ensure_enrollment_code);
    let exe = env::current_exe().ok()?;
    let stdout = fs::File::create(console_state_dir().join("console.log")).ok()?;
    let stderr = fs::File::create(console_state_dir().join("console.err.log")).ok()?;
    let child = Command::new(exe)
        .arg("--agent")
        .env_remove("TUNNEL_TOKEN")
        .env_remove("TUNNEL_SERVER_URL")
        .stdout(stdout)
        .stderr(stderr)
        .creation_flags(0x0800_0000) // CREATE_NO_WINDOW: hidden background worker
        .spawn()
        .ok()?;
    let pid = child.id();
    let _ = write_console_pid(pid);
    // Give the worker a short startup window; if it exits immediately (for
    // example a panic on this machine), say so instead of reporting success.
    std::thread::sleep(Duration::from_millis(400));
    if !process_is_running(pid) {
        println!("WARNING: agent exited right after start (PID {pid}).");
        println!(
            "Check the worker logs: {}",
            console_state_dir().join("console.err.log").display()
        );
    }
    println!("Agent started (PID {pid}).");
    if let Some(code) = enrollment_code {
        println!("==============================================");
        println!("设备尚未注册，注册码：{code}");
        println!("请管理员在管理端「设备注册」页输入该注册码批准，批准后自动接入。");
        println!("==============================================");
    }
    Some(pid)
}

#[cfg(not(windows))]
fn start_agent_process() -> Option<u32> {
    println!("Client console is supported on Windows only.");
    None
}

fn console_stop() {
    match read_console_pid() {
        Some(pid) if process_is_running(pid) => {
            stop_process(pid);
            let _ = fs::remove_file(console_pid_file());
            println!("Agent stopped.");
        }
        _ => {
            let _ = fs::remove_file(console_pid_file());
            println!("Agent is not running.");
        }
    }
}

fn console_status() {
    match read_console_pid() {
        Some(pid) if process_is_running(pid) => println!("Agent process: RUNNING (PID {pid})"),
        _ => println!("Agent process: stopped"),
    }
    let credentials = load_credentials();
    match credentials.get("SERVER_URL") {
        Some(url) => println!("Server       : {url}"),
        None => println!("Server       : not configured (first start will ask)"),
    }
    match credentials.get("TOKEN") {
        Some(_) => println!("Credentials  : token issued (enrolled)"),
        None => println!("Credentials  : pending enrollment"),
    }
    println!(
        "Service      : {}",
        if service_is_running() {
            "running (TunnelAgent)"
        } else {
            "not running"
        }
    );
}

/// `settings` command: prints the effective agent settings. Values pushed by
/// the server are persisted to the credentials file on every `SettingsSync`,
/// so this works whether or not the agent process is currently running.
fn console_settings() {
    let settings = AgentConfig::from_env().to_agent_settings();
    let credentials = load_credentials();
    match credentials
        .get("SETTINGS_SYNCED_AT")
        .and_then(|value| value.parse::<u64>().ok())
    {
        Some(synced_at) => {
            println!("服务器下发设置(同步时间 {})", format_unix_time(synced_at));
        }
        None => {
            println!("尚未收到服务器下发设置(当前为本地默认)");
        }
    }
    println!("  设备名称    : {}", settings.device_name);
    println!("  服务器地址  : {}", settings.server_url);
    println!("  数据通道数  : {}", settings.data_channels);
    println!("  心跳间隔    : {} 秒", settings.heartbeat_secs);
    println!("  PONG 超时   : {} 秒", settings.pong_timeout_secs);
    println!("  重连最小间隔: {} 秒", settings.reconnect_min_secs);
    println!("  重连最大间隔: {} 秒", settings.reconnect_max_secs);
    println!("  日志级别    : {}", settings.log_level);
}

/// `traffic` command: asks the running agent for a live per-channel snapshot
/// through its named pipe, then prints each channel's up/down/total bytes.
#[cfg(windows)]
fn console_traffic() {
    let Some(pid) = read_console_pid() else {
        println!("代理未运行,无法获取实时流量。");
        return;
    };
    if !process_is_running(pid) {
        println!("代理未运行,无法获取实时流量。");
        return;
    }
    let Ok(runtime) = tokio::runtime::Builder::new_current_thread()
        .enable_all()
        .build()
    else {
        println!("无法启动流量查询运行时。");
        return;
    };
    match runtime.block_on(fetch_traffic_snapshot(pid)) {
        Ok(snapshot) => print_traffic(&snapshot),
        Err(error) => println!("无法获取实时流量: {error}"),
    }
}

#[cfg(not(windows))]
fn console_traffic() {
    println!("traffic 命令仅在 Windows 上可用。");
}

/// Connects to the agent's named pipe and reads one snapshot response.
#[cfg(windows)]
async fn fetch_traffic_snapshot(pid: u32) -> io::Result<IpcSnapshot> {
    use tokio::io::{AsyncReadExt, AsyncWriteExt};
    let path = format!(r"\\.\pipe\TunnelControl-agent-{pid}");
    // Opening a named pipe is synchronous; retry briefly because the agent's
    // IPC server recreates its pipe instance between accepted connections.
    let mut client = None;
    for _ in 0..5 {
        match ClientOptions::new().open(&path) {
            Ok(opened) => {
                client = Some(opened);
                break;
            }
            Err(error)
                if matches!(
                    error.kind(),
                    io::ErrorKind::NotFound | io::ErrorKind::WouldBlock
                ) =>
            {
                tokio::time::sleep(Duration::from_millis(100)).await;
            }
            Err(error) => {
                return Err(io::Error::new(io::ErrorKind::NotFound, error.to_string()));
            }
        }
    }
    let Some(mut client) = client else {
        return Err(io::Error::new(
            io::ErrorKind::NotFound,
            "agent IPC pipe unavailable",
        ));
    };
    client.write_all(b"{\"cmd\":\"snapshot\"}\n").await?;
    client.flush().await?;
    let mut response = Vec::new();
    let mut buffer = [0_u8; 4096];
    loop {
        let read = tokio::time::timeout(Duration::from_secs(2), client.read(&mut buffer))
            .await
            .map_err(|_| io::Error::new(io::ErrorKind::TimedOut, "IPC read timed out"))??;
        if read == 0 {
            break;
        }
        response.extend_from_slice(&buffer[..read]);
        if response.contains(&b'\n') {
            break;
        }
        if response.len() > MAX_FRAME_BYTES {
            return Err(io::Error::new(
                io::ErrorKind::InvalidData,
                "IPC response too large",
            ));
        }
    }
    let line = response
        .split(|byte| *byte == b'\n')
        .next()
        .unwrap_or_default();
    serde_json::from_slice(line)
        .map_err(|error| io::Error::new(io::ErrorKind::InvalidData, error.to_string()))
}

fn print_traffic(snapshot: &IpcSnapshot) {
    println!("流量统计(截至 {})", format_unix_time(unix_now()));
    if snapshot.channels.is_empty() {
        println!("  尚无数据通道流量统计。");
    } else {
        for channel in &snapshot.channels {
            let state = if channel.connected {
                "在线"
            } else {
                "离线"
            };
            println!(
                "  通道 {} : 上行 {} / 下行 {} / 合计 {} ({state})",
                channel.channel_id,
                format_bytes(channel.up_bytes),
                format_bytes(channel.down_bytes),
                format_bytes(channel.up_bytes.saturating_add(channel.down_bytes)),
            );
        }
    }
    println!(
        "  合计   : 上行 {} / 下行 {} / 总计 {}",
        format_bytes(snapshot.totals.up_bytes),
        format_bytes(snapshot.totals.down_bytes),
        format_bytes(snapshot.totals.total_bytes),
    );
}

/// Formats a byte count with adaptive 1024-based units (B/KB/MB/GB/TB),
/// keeping one decimal place for values that need it.
fn format_bytes(bytes: u64) -> String {
    const UNITS: [&str; 5] = ["B", "KB", "MB", "GB", "TB"];
    if bytes < 1024 {
        return format!("{bytes} B");
    }
    let mut value = bytes as f64;
    let mut unit = 0;
    while value >= 1024.0 && unit < UNITS.len() - 1 {
        value /= 1024.0;
        unit += 1;
    }
    let text = format!("{value:.1}");
    format!("{} {}", text.trim_end_matches(".0"), UNITS[unit])
}

fn unix_now() -> u64 {
    SystemTime::now()
        .duration_since(SystemTime::UNIX_EPOCH)
        .map(|duration| duration.as_secs())
        .unwrap_or(0)
}

/// Formats a Unix timestamp as local wall-clock time.
fn format_unix_time(secs: u64) -> String {
    chrono::DateTime::from_timestamp(secs as i64, 0)
        .map(|time| {
            time.with_timezone(&chrono::Local)
                .format("%Y-%m-%d %H:%M:%S")
                .to_string()
        })
        .unwrap_or_else(|| format!("{secs} (Unix)"))
}

fn console_help() {
    println!("Commands:");
    println!("  start     start the agent if it is not running");
    println!("  stop      terminate the agent");
    println!("  restart   terminate and start again");
    println!("  reset     stop the agent and delete ALL local data (re-enroll on next start)");
    println!("  status    show process/service/credential state");
    println!("  settings  show the settings pushed by the server");
    println!("  traffic   show live per-channel traffic totals");
    println!("  logs      print the latest agent log lines");
    println!("  exit      leave the console (the agent keeps running)");
    println!("  help      show this help");
}

fn console_reset() {
    console_stop();
    if let Err(error) = reset_local_data() {
        println!("Reset failed: {error}");
    } else {
        println!("Local agent data has been reset. Type 'start' to choose a server and re-enroll.");
    }
}

/// Client console: one-click entry point. First start prompts for the server
/// (official LineWeb or custom), then starts the agent as a hidden background
/// process and keeps an interactive command prompt.
fn run_console() {
    setup_logging(true);
    let _ = fs::create_dir_all(console_log_dir());
    // Point every credential/log helper at the per-user console state so no
    // elevation is needed. Set once, single-threaded, before any helper runs.
    unsafe {
        env::set_var("TUNNEL_CREDENTIALS_FILE", console_credentials_file());
        env::set_var("TUNNEL_LOG_DIR", console_log_dir());
    }
    println!("==============================================");
    println!("  Tunnel Control Client");
    println!("==============================================");
    console_help();
    start_agent_process();
    loop {
        let Some(line) = read_prompt("tunnel-client") else {
            break;
        };
        match line.as_str() {
            "start" => {
                start_agent_process();
            }
            "stop" => console_stop(),
            "restart" => {
                console_stop();
                std::thread::sleep(Duration::from_millis(300));
                start_agent_process();
            }
            "reset" => console_reset(),
            "status" => console_status(),
            "settings" => console_settings(),
            "traffic" => console_traffic(),
            "logs" => main_logs(false, 60),
            "exit" => {
                println!(
                    "Exiting. The agent keeps running in the background; type 'stop' to terminate it next time."
                );
                break;
            }
            "help" => console_help(),
            "" => {}
            _ => println!("Unknown command '{line}'. Type 'help'."),
        }
    }
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
        // Process-wide state: pushed settings and traffic counters must
        // survive reconnects, so the status is created once instead of per
        // session. Only connection parameters are re-read from disk below.
        let status = AgentStatus::new(&AgentConfig::from_env());
        #[cfg(windows)]
        tokio::spawn(ipc_server(status.clone()));
        loop {
            // Re-read the config every session so enrollment and pushed
            // settings (persisted to the credentials file) take effect on the
            // next connect without a process restart.
            let config = AgentConfig::from_env();
            let outcome = run(&config, &status).await;
            match outcome {
                // Enrollment approved or settings require a reconnect:
                // connect again immediately with the fresh config.
                Ok(RunOutcome::ReconnectNow) => {
                    attempt = 0;
                    continue;
                }
                // Remote restart: console workers spawn a fresh hidden
                // process; service mode exits and the SCM failure recovery
                // actions bring the service back within a few seconds.
                Ok(RunOutcome::Restarting { restart_id }) => {
                    tracing::info!(%restart_id, "restarting agent process");
                    if !restart_agent_process() {
                        // Could not replace the console worker; stay online
                        // instead of taking the device down.
                        attempt = 0;
                        continue;
                    }
                    std::thread::sleep(Duration::from_millis(500));
                    // Non-zero exit makes the SCM failure recovery kick in
                    // for service mode; console workers are already replaced.
                    std::process::exit(1);
                }
                Ok(RunOutcome::Disconnected) => {
                    tracing::info!("control connection closed; backing off");
                }
                Err(error) => {
                    tracing::warn!(%error, "agent disconnected; retrying");
                }
            }
            let fraction = rand::thread_rng().gen_range(0.7..=1.3);
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

/// Restarts the agent process in place. Console mode (`--agent`) spawns a
/// fresh hidden worker and updates the pid file before the old process
/// exits. Service mode needs no spawn: the Windows SCM was configured with
/// `failure restart/5000` at install time, so exiting the process makes the
/// service restart automatically. Returns false only when a console-mode
/// worker could not be spawned, in which case the caller keeps running.
fn restart_agent_process() -> bool {
    #[cfg(windows)]
    if env::args().any(|argument| argument == "--agent") {
        let Some(exe) = env::current_exe().ok() else {
            return false;
        };
        let stdout = fs::File::create(console_state_dir().join("console.log")).ok();
        let stderr = fs::File::create(console_state_dir().join("console.err.log")).ok();
        let mut command = Command::new(exe);
        command
            .arg("--agent")
            .env_remove("TUNNEL_TOKEN")
            .env_remove("TUNNEL_SERVER_URL")
            .creation_flags(0x0800_0000); // CREATE_NO_WINDOW
        if let (Some(stdout), Some(stderr)) = (stdout, stderr) {
            command.stdout(stdout).stderr(stderr);
        }
        if let Ok(child) = command.spawn() {
            let _ = fs::write(console_pid_file(), child.id().to_string());
            tracing::info!(
                pid = child.id(),
                "fresh console-mode agent spawned; old process exiting"
            );
            return true;
        }
        tracing::error!("could not spawn fresh console-mode agent; staying online");
        return false;
    }
    true
}

/// Windows named pipe used for console <-> agent queries. The PID keeps the
/// name collision-free across user sessions and stale agent processes; the
/// console reads the same PID from its `agent.pid` file.
#[cfg(windows)]
fn agent_pipe_name() -> String {
    format!(r"\\.\pipe\TunnelControl-agent-{}", std::process::id())
}

/// Serves one-shot `snapshot` requests from the client console. Each accepted
/// connection is handled in its own task and closed after the response, so
/// the console always reads counters as of the moment its command runs.
#[cfg(windows)]
async fn ipc_server(status: AgentStatus) {
    let path = agent_pipe_name();
    loop {
        let server = match ServerOptions::new().create(&path) {
            Ok(server) => server,
            Err(error) => {
                tracing::warn!(%error, "IPC pipe create failed; retrying");
                tokio::time::sleep(Duration::from_secs(2)).await;
                continue;
            }
        };
        match server.connect().await {
            Ok(()) => {
                let status = status.clone();
                tokio::spawn(async move {
                    if let Err(error) = handle_ipc_client(server, status).await {
                        tracing::debug!(%error, "IPC client session ended");
                    }
                });
            }
            Err(error) => {
                tracing::warn!(%error, "IPC pipe accept failed");
                tokio::time::sleep(Duration::from_millis(100)).await;
            }
        }
    }
}

/// Reads one newline-delimited JSON request, answers with a `snapshot`
/// payload, and closes the connection.
#[cfg(windows)]
async fn handle_ipc_client(mut server: NamedPipeServer, status: AgentStatus) -> io::Result<()> {
    use tokio::io::{AsyncReadExt, AsyncWriteExt};
    let mut request = Vec::new();
    let mut buffer = [0_u8; 512];
    loop {
        let read = server.read(&mut buffer).await?;
        if read == 0 {
            break;
        }
        request.extend_from_slice(&buffer[..read]);
        if request.contains(&b'\n') {
            break;
        }
        if request.len() > 4096 {
            return Ok(());
        }
    }
    if request.is_empty() {
        return Ok(());
    }
    let Ok(IpcRequest { cmd }) = serde_json::from_slice(&request) else {
        return Ok(());
    };
    if cmd != "snapshot" {
        return Ok(());
    }
    let snapshot = build_ipc_snapshot(&status).await;
    let response = serde_json::to_vec(&snapshot)
        .map_err(|error| io::Error::new(io::ErrorKind::InvalidData, error.to_string()))?;
    server.write_all(&response).await?;
    server.write_all(b"\n").await?;
    server.flush().await?;
    Ok(())
}

/// Builds the live snapshot: effective settings plus per-channel byte totals
/// accumulated since the agent process started.
async fn build_ipc_snapshot(status: &AgentStatus) -> IpcSnapshot {
    let settings = status.settings.read().await.clone();
    let settings_synced_at = *status.settings_synced_at.lock().unwrap();
    let mut channels: Vec<IpcChannelStat> = status
        .traffic
        .channels
        .read()
        .await
        .iter()
        .map(|(channel_id, counters)| {
            let (up_bytes, down_bytes, connected) = counters.snapshot();
            IpcChannelStat {
                channel_id: *channel_id,
                up_bytes,
                down_bytes,
                connected,
            }
        })
        .collect();
    channels.sort_by_key(|channel| channel.channel_id);
    let up_bytes: u64 = channels.iter().map(|channel| channel.up_bytes).sum();
    let down_bytes: u64 = channels.iter().map(|channel| channel.down_bytes).sum();
    IpcSnapshot {
        settings,
        settings_synced_at,
        channels,
        totals: IpcTrafficTotals {
            up_bytes,
            down_bytes,
            total_bytes: up_bytes.saturating_add(down_bytes),
        },
    }
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

/// Resets every piece of local agent data: issued token, pending enrollment
/// code, bootstrap `agent.env`, service logs, and the one-click script state
/// under %LOCALAPPDATA%. Running agent instances (Windows service or script
/// mode) are stopped first so file handles are released; the service itself
/// is kept so `--install` can simply restart it. Run as Administrator when
/// the agent was installed under Program Files.
fn reset_local_data() -> Result<(), Box<dyn std::error::Error>> {
    #[cfg(windows)]
    {
        let _ = Command::new("sc.exe")
            .args(["stop", "TunnelAgent"])
            .status();
        std::thread::sleep(Duration::from_secs(1));
        // Stop other agent instances (one-click script mode) but never this
        // reset process itself.
        let own_pid = std::process::id();
        let script = format!(
            "Get-Process tunnel-agent -ErrorAction SilentlyContinue | \
             Where-Object {{ $_.Id -ne {own_pid} }} | Stop-Process -Force"
        );
        let _ = Command::new("powershell")
            .args(["-NoProfile", "-Command", &script])
            .status();
        std::thread::sleep(Duration::from_millis(500));
    }
    // One-click script mode state: credentials, logs, pid file, console logs.
    if let Some(local) = env::var_os("LOCALAPPDATA") {
        let _ = fs::remove_dir_all(PathBuf::from(local).join("TunnelControl"));
    }
    // Service-mode credentials (PROGRAMDATA by default, or the override env).
    let credentials = credentials_path();
    if credentials.exists() {
        fs::remove_file(&credentials)?;
    }
    // Bootstrap config next to the binary (server URL / legacy token).
    let bootstrap = env::current_exe()
        .ok()
        .and_then(|exe| exe.parent().map(|parent| parent.join("agent.env")))
        .unwrap_or_else(|| PathBuf::from("agent.env"));
    let _ = fs::remove_file(&bootstrap);
    // Rotating service logs.
    if let Some(dir) = log_dir() {
        let _ = fs::remove_dir_all(&dir);
    }
    println!("Local agent data has been reset.");
    println!("The next start will require device-code enrollment again.");
    Ok(())
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
    /// The server asked this agent to restart its process. The caller must
    /// respawn (console mode) or exit (service mode, SCM recovery restarts).
    Restarting { restart_id: String },
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
    let last_ping_sent = Arc::new(std::sync::Mutex::new(None::<Instant>));
    let last_rtt_ms = Arc::new(std::sync::Mutex::new(0_u32));
    let reader_done = Arc::new(tokio::sync::Notify::new());
    let settings_changed = Arc::new(tokio::sync::Notify::new());
    let restart_requested = Arc::new(std::sync::Mutex::new(None::<String>));

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
    let reader_ping_sent = last_ping_sent.clone();
    let reader_rtt = last_rtt_ms.clone();
    let reader_config = config.clone();
    let reader_status = status.clone();
    let reader_data_tasks = data_tasks.clone();
    let reader_done_notify = reader_done.clone();
    let reader_settings_changed = settings_changed.clone();
    let reader_restart_requested = restart_requested.clone();
    let reader_task = tokio::spawn(async move {
        let mut data_channels_opened = false;
        while let Some(Ok(message)) = read.next().await {
            match message {
                Message::Pong(_) => {
                    if let Ok(mut guard) = reader_pong.lock() {
                        *guard = Instant::now();
                    }
                    if let Ok(mut ping_sent) = reader_ping_sent.lock() {
                        if let Some(sent) = ping_sent.take() {
                            let rtt_ms =
                                sent.elapsed().as_millis().min(u128::from(u32::MAX)) as u32;
                            if let Ok(mut rtt_guard) = reader_rtt.lock() {
                                *rtt_guard = rtt_ms;
                            }
                        }
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
                        let reconnect_required = settings_reconnect_decision(&current, &settings);
                        let synced_at = unix_now();
                        let mut updates = HashMap::new();
                        // Empty server_url means "not configured"; keep the
                        // local bootstrap address instead of wiping it.
                        if !settings.server_url.is_empty() {
                            updates.insert("SERVER_URL".to_string(), settings.server_url.clone());
                        }
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
                        updates.insert("SETTINGS_SYNCED_AT".to_string(), synced_at.to_string());
                        if save_credentials(&updates).is_err() {
                            tracing::warn!("could not persist pushed settings");
                        }
                        *reader_status.settings_synced_at.lock().unwrap() = Some(synced_at);
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
                        let (tx, rx) = mpsc::channel::<Vec<u8>>(STREAM_QUEUE_FRAMES);
                        // Register the stream before spawning the bridge so the
                        // first data frame following StreamOpen is never dropped.
                        reader_streams.write().await.insert(
                            id,
                            StreamEntry {
                                tx: tx.clone(),
                                slot: Arc::new(Mutex::new(StreamSlot::default())),
                            },
                        );
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
                            .map(|(_, frames, _)| frames)
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
                            drop_stream(
                                &reader_streams,
                                &reader_connections,
                                id,
                                reason.as_deref().unwrap_or("server_close"),
                            )
                            .await;
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
                    Ok(ControlMessage::RestartAgent { restart_id, reason }) => {
                        if let Ok(mut pending_restart) = reader_restart_requested.lock() {
                            *pending_restart = Some(restart_id.clone());
                        }
                        tracing::warn!(
                            %restart_id,
                            reason = reason.as_deref().unwrap_or("admin_request"),
                            "remote restart requested; stopping agent"
                        );
                        // Tell the server we are stopping, then give the
                        // control writer a moment to flush the progress
                        // message before the session tears down.
                        let progress = ControlMessage::RestartProgress {
                            restart_id,
                            progress: 30,
                            phase: "stopping".into(),
                            message: Some("代理已收到重启指令,正在停止本地隧道".into()),
                        };
                        if let Ok(payload) = encode(&progress) {
                            let _ = reader_control
                                .send(Message::Text(
                                    String::from_utf8_lossy(&payload).into_owned().into(),
                                ))
                                .await;
                        }
                        tokio::time::sleep(Duration::from_millis(300)).await;
                        reader_settings_changed.notify_one();
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
            .retain(|_, (at, _, _)| now.duration_since(*at) < Duration::from_secs(10));
        // After wake-from-sleep the TCP connection may be dead while the OS
        // keeps retransmitting; require a fresh pong or reconnect promptly.
        let pong_timeout_secs = status.settings.read().await.pong_timeout_secs;
        if last_pong.lock().unwrap().elapsed() > Duration::from_secs(pong_timeout_secs) {
            break;
        }
        let latency_ms = last_rtt_ms.lock().map(|rtt| *rtt).unwrap_or(0);
        let heartbeat = ControlMessage::Heartbeat {
            version: PROTOCOL_VERSION,
            latency_ms,
        };
        if let Ok(payload) = encode(&heartbeat) {
            // The pong timeout still guards a dead connection.
            let _ = control_tx.try_send(Message::Text(
                String::from_utf8_lossy(&payload).into_owned().into(),
            ));
        }
        if control_tx
            .try_send(Message::Ping(Vec::new().into()))
            .is_ok()
        {
            if let Ok(mut ping_sent) = last_ping_sent.lock() {
                *ping_sent = Some(Instant::now());
            }
        }
    }
    let restart_id = restart_requested.lock().unwrap().clone();
    status.connections.write().await.clear();
    for task in data_tasks.lock().await.drain(..) {
        task.abort();
    }
    // The control session is ending; every data channel is gone even though
    // its process-wide counters stay for the `traffic` command.
    for counters in status.traffic.channels.read().await.values() {
        counters.connected.store(false, Ordering::Relaxed);
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
        if let Some(restart_id) = restart_id {
            Ok(RunOutcome::Restarting { restart_id })
        } else {
            Ok(RunOutcome::ReconnectNow)
        }
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
/// pong timeout. Applied to the control socket and every data socket, for
/// both plain (`ws://`) and TLS (`wss://`) connections.
fn enable_tcp_keepalive(
    socket: &tokio_tungstenite::WebSocketStream<
        tokio_tungstenite::MaybeTlsStream<tokio::net::TcpStream>,
    >,
) {
    match socket.get_ref() {
        tokio_tungstenite::MaybeTlsStream::Plain(tcp) => apply_tcp_keepalive(tcp),
        tokio_tungstenite::MaybeTlsStream::Rustls(tls) => apply_tcp_keepalive(tls.get_ref().0),
        // Non-exhaustive upstream enum; keepalive stays best-effort for any
        // future TLS backend.
        _ => {}
    }
}

/// Sets nodelay and a 10s TCP keepalive on the underlying socket so the OS
/// probes a half-open link regardless of whether the WebSocket is encrypted.
fn apply_tcp_keepalive(tcp: &tokio::net::TcpStream) {
    let _ = tcp.set_nodelay(true);
    let socket_ref = socket2::SockRef::from(tcp);
    let _ = socket_ref
        .set_tcp_keepalive(&socket2::TcpKeepalive::new().with_time(Duration::from_secs(10)));
}

/// One data WebSocket: binds to the control session with `DataBind`, waits for
/// `DataBound`, then relays binary frames until the socket drops. On failure
/// it retries with exponential backoff and jitter; the counter resets once a
/// channel binds. The task is aborted when the control run ends.
async fn data_channel_task(
    config: AgentConfig,
    status: AgentStatus,
    streams: StreamMap,
    connections: ConnectionMap,
    control: mpsc::Sender<Message>,
    pending: PendingMap,
) {
    let mut attempt = 0_u32;
    loop {
        match connect_async(&config.data_server).await {
            Ok((socket, _)) => {
                enable_tcp_keepalive(&socket);
                let (mut sink, mut source) = socket.split();
                let bind = ControlMessage::DataBind {
                    token: config.token.clone(),
                };
                let Ok(payload) = encode(&bind) else {
                    let delay = data_channel_backoff(attempt);
                    attempt = attempt.saturating_add(1);
                    tokio::time::sleep(delay).await;
                    continue;
                };
                if sink
                    .send(Message::Text(
                        String::from_utf8_lossy(&payload).into_owned().into(),
                    ))
                    .await
                    .is_err()
                {
                    let delay = data_channel_backoff(attempt);
                    attempt = attempt.saturating_add(1);
                    tokio::time::sleep(delay).await;
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
                    let delay = data_channel_backoff(attempt);
                    attempt = attempt.saturating_add(1);
                    tokio::time::sleep(delay).await;
                    continue;
                };
                attempt = 0;
                let (tx, mut rx) = mpsc::channel::<Message>(DATA_CHANNEL_QUEUE_FRAMES);
                status
                    .data_channels
                    .write()
                    .await
                    .insert(channel_id, tx.clone());
                // Get-or-create the process-wide counters for this channel
                // id so a reconnect keeps accumulating instead of resetting.
                let counters = status
                    .traffic
                    .channels
                    .write()
                    .await
                    .entry(channel_id)
                    .or_insert_with(|| Arc::new(ChannelCounters::default()))
                    .clone();
                counters.connected.store(true, Ordering::Relaxed);
                let writer_streams = streams.clone();
                let writer_counters = counters.clone();
                let writer = tokio::spawn(async move {
                    while let Some(message) = rx.recv().await {
                        // The frame has left the shared queue; return the
                        // stream's quota so its bridge can enqueue more
                        // without monopolizing the channel.
                        let mut sent_bytes = 0_usize;
                        if let Message::Binary(bytes) = &message {
                            if let Ok((id, payload)) = decode_stream_data(bytes) {
                                release_stream_slot_agent(&writer_streams, id).await;
                                sent_bytes = payload.len();
                            }
                        }
                        if sink.send(message).await.is_err() {
                            break;
                        }
                        if sent_bytes > 0 {
                            writer_counters
                                .up_bytes
                                .fetch_add(sent_bytes as u64, Ordering::Relaxed);
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
                            counters
                                .down_bytes
                                .fetch_add(data.len() as u64, Ordering::Relaxed);
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
                counters.connected.store(false, Ordering::Relaxed);
                tracing::warn!(channel_id, "data channel lost; reconnecting");
                let delay = data_channel_backoff(attempt);
                attempt = attempt.saturating_add(1);
                tokio::time::sleep(delay).await;
            }
            Err(error) => {
                tracing::warn!(%error, "data channel connect failed; retrying");
                let delay = data_channel_backoff(attempt);
                attempt = attempt.saturating_add(1);
                tokio::time::sleep(delay).await;
            }
        }
    }
}

/// Routes one binary frame arriving on a data socket to its stream. TCP
/// frames wait in the stream's bounded queue so backpressure reaches the
/// remote peer; UDP datagrams are dropped when the queue is full.
async fn route_agent_binary(
    streams: &StreamMap,
    connections: &ConnectionMap,
    control: &mpsc::Sender<Message>,
    pending: &PendingMap,
    id: u128,
    data: &[u8],
) {
    route_agent_binary_with_timeout(
        streams,
        connections,
        control,
        pending,
        id,
        data,
        TCP_SEND_TIMEOUT,
    )
    .await
}

/// Buffers one frame that arrived before its `StreamOpen` (cross-socket
/// ordering is not guaranteed). `byte_budget` is a warning threshold, not a
/// drop point: below the hard limit TCP must never lose bytes before
/// registration, so once the budget is crossed the buffer grows and we warn
/// once. `hard_limit` is the absolute ceiling: a stream that never registers
/// must not consume unbounded memory, so frames past it are dropped with an
/// error log. The 10s pending expiry reclaims entries whose `StreamOpen`
/// never arrives.
async fn buffer_pending_frame(
    pending: &PendingMap,
    id: u128,
    data: &[u8],
    byte_budget: usize,
    hard_limit: usize,
) {
    let mut guard = pending.write().await;
    let entry = guard
        .entry(id)
        .or_insert_with(|| (Instant::now(), Vec::new(), 0));
    if entry.2 + data.len() > hard_limit {
        tracing::error!(
            stream_id = %id,
            buffered_bytes = entry.2,
            "pending stream buffer hit hard limit; dropping frame"
        );
        return;
    }
    if entry.2 < byte_budget && entry.2 + data.len() >= byte_budget {
        tracing::warn!(
            stream_id = %id,
            buffered_bytes = entry.2 + data.len(),
            "pending stream buffer exceeded {byte_budget} bytes; growing instead of dropping"
        );
    }
    entry.1.push(data.to_vec());
    entry.2 += data.len();
}

async fn route_agent_binary_with_timeout(
    streams: &StreamMap,
    connections: &ConnectionMap,
    control: &mpsc::Sender<Message>,
    pending: &PendingMap,
    id: u128,
    data: &[u8],
    timeout: Duration,
) {
    let tx = {
        let map = streams.read().await;
        map.get(&id).map(|entry| entry.tx.clone())
    };
    let Some(tx) = tx else {
        // `StreamOpen` travels on the control socket while data frames arrive
        // on data sockets; the first frames can beat the registration. Buffer
        // them briefly so the StreamOpen handler can flush them once the
        // stream exists. The stream kind is unknown before registration, so
        // every frame is buffered (dropping would corrupt TCP byte order);
        // past the warning budget it grows, and past the hard limit it is
        // dropped with an error.
        buffer_pending_frame(
            pending,
            id,
            data,
            PENDING_STREAM_BYTES,
            PENDING_STREAM_HARD_BYTES,
        )
        .await;
        return;
    };
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
        let _ = tx.try_send(data.to_vec());
        return;
    }
    match tokio::time::timeout(timeout, tx.send(data.to_vec())).await {
        Ok(Ok(())) => {}
        Ok(Err(_)) => {
            // The local bridge went away while enqueuing; close the stream.
            drop_stream(streams, connections, id, "local_channel_closed").await;
            send_close(control, id.to_string(), Some("local_channel_closed".into()));
        }
        Err(_) => {
            // The local service is too slow to drain its bounded queue; close
            // after the timeout instead of dropping bytes or stalling the
            // shared data channel forever.
            drop_stream(streams, connections, id, "local_send_timeout").await;
            send_close(control, id.to_string(), Some("local_send_timeout".into()));
        }
    }
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
    // Small interactive packets (SSH, HTTP, RDP) are latency-sensitive; never
    // let Nagle delay them on the local service socket.
    let _ = socket.set_nodelay(true);
    let (mut reader, mut writer) = socket.into_split();
    let write_task = tokio::spawn(async move {
        while let Some(data) = rx.recv().await {
            if writer.write_all(&data).await.is_err() {
                break;
            }
        }
    });
    let mut buffer = [0_u8; TCP_CHUNK_SIZE];
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
                // Hold this stream's share of the shared channel queue so one
                // bulk upload cannot head-of-line block the other streams.
                if !acquire_stream_slot_agent(&streams, id).await {
                    break;
                }
                if !send_agent_channel_with_stream_alive(
                    &streams,
                    id,
                    &data,
                    Message::Binary(frame.into()),
                )
                .await
                {
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

/// Waits until the stream has fewer than `STREAM_CHANNEL_QUOTA` frames waiting
/// in the channel writer queue, then reserves one slot. Returns false if the
/// stream entry is removed while waiting (the bridge should stop).
async fn acquire_stream_slot_agent(streams: &StreamMap, id: u128) -> bool {
    loop {
        let slot = {
            let map = streams.read().await;
            match map.get(&id) {
                Some(entry) => entry.slot.clone(),
                None => return false,
            }
        };
        let notify = {
            let mut state = slot.lock().await;
            if state.outstanding < STREAM_CHANNEL_QUOTA {
                state.outstanding += 1;
                return true;
            }
            state.notify.clone()
        };
        notify.notified().await;
        if !streams.read().await.contains_key(&id) {
            return false;
        }
    }
}

/// Releases one reserved slot after the channel writer dequeued the frame and
/// wakes the stream's bridge so it can enqueue more.
async fn release_stream_slot_agent(streams: &StreamMap, id: u128) {
    let slot = {
        let map = streams.read().await;
        map.get(&id).map(|entry| entry.slot.clone())
    };
    if let Some(slot) = slot {
        let mut state = slot.lock().await;
        state.outstanding = state.outstanding.saturating_sub(1);
        state.notify.notify_waiters();
    }
}

/// Reserves space on the shared data-channel writer queue while periodically
/// checking that the stream is still registered, so a full channel cannot
/// strand the bridge after the stream was removed. `reserve` is
/// cancellation-safe: a cancelled attempt leaves no message in the queue.
async fn send_agent_channel_with_stream_alive(
    streams: &StreamMap,
    id: u128,
    data: &mpsc::Sender<Message>,
    message: Message,
) -> bool {
    let mut check = tokio::time::interval(Duration::from_secs(1));
    check.tick().await; // consume the immediate first tick
    loop {
        let reserve = data.reserve();
        tokio::select! {
            result = reserve => match result {
                Ok(permit) => {
                    let _ = permit.send(message);
                    return true;
                }
                Err(_) => return false,
            },
            _ = check.tick() => {
                if !streams.read().await.contains_key(&id) {
                    return false;
                }
            }
        }
    }
}

async fn drop_stream(streams: &StreamMap, connections: &ConnectionMap, id: u128, reason: &str) {
    let slot = {
        let mut map = streams.write().await;
        map.remove(&id).map(|entry| entry.slot)
    };
    if let Some(slot) = slot {
        let mut state = slot.lock().await;
        state.outstanding = 0;
        state.notify.notify_waiters();
    }
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

    #[test]
    fn ps_output_matching_strips_utf16le_nuls() {
        // Windows PowerShell 5.1 emits UTF-16LE on a redirected stdout:
        // "tunnel-agent" becomes t, NUL, u, NUL, n, NUL, ...
        let utf16le = b"t\0u\0n\0n\0e\0l\0-\0a\0g\0e\0n\0t\0\r\0\n\0";
        assert!(ps_stdout_contains_bytes(utf16le, "tunnel-agent"));
        assert!(ps_stdout_contains_bytes(b"True\r\n", "True"));
        assert!(!ps_stdout_contains_bytes(b"", "tunnel-agent"));
    }

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
        streams.write().await.insert(
            42,
            StreamEntry {
                tx: tx.clone(),
                slot: Arc::new(Mutex::new(StreamSlot::default())),
            },
        );
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
        streams.write().await.insert(
            43,
            StreamEntry {
                tx: tx.clone(),
                slot: Arc::new(Mutex::new(StreamSlot::default())),
            },
        );
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
        streams.write().await.insert(
            7,
            StreamEntry {
                tx: tx.clone(),
                slot: Arc::new(Mutex::new(StreamSlot::default())),
            },
        );
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

    #[tokio::test]
    async fn tcp_route_waits_when_local_queue_is_full() {
        let streams: StreamMap = Arc::new(RwLock::new(HashMap::new()));
        let connections: ConnectionMap = Arc::new(RwLock::new(HashMap::new()));
        let pending: PendingMap = Arc::new(RwLock::new(HashMap::new()));
        let (control, _control_rx) = mpsc::channel::<Message>(8);
        let id: u128 = 88;
        let (tx, mut rx) = mpsc::channel::<Vec<u8>>(1);
        streams.write().await.insert(
            id,
            StreamEntry {
                tx,
                slot: Arc::new(Mutex::new(StreamSlot::default())),
            },
        );
        connections
            .write()
            .await
            .insert(id, ConnectionInfo { kind: "tcp".into() });
        route_agent_binary(&streams, &connections, &control, &pending, id, b"first").await;
        // The local queue is now full; routing must wait (backpressure)
        // instead of dropping the frame or closing the stream.
        let routing = tokio::spawn({
            let streams = streams.clone();
            let connections = connections.clone();
            let control = control.clone();
            let pending = pending.clone();
            async move {
                route_agent_binary(&streams, &connections, &control, &pending, id, b"second").await;
            }
        });
        tokio::time::sleep(Duration::from_millis(100)).await;
        assert!(
            streams.read().await.contains_key(&id),
            "saturated TCP stream must stay registered while backpressure applies"
        );
        // Draining the local queue lets the waiting frame through, in order.
        assert_eq!(rx.recv().await.as_deref(), Some(b"first".as_slice()));
        routing.await.unwrap();
        assert_eq!(rx.recv().await.as_deref(), Some(b"second".as_slice()));
        assert!(streams.read().await.contains_key(&id));
    }

    #[tokio::test]
    async fn tcp_route_times_out_and_closes_stream() {
        let streams: StreamMap = Arc::new(RwLock::new(HashMap::new()));
        let connections: ConnectionMap = Arc::new(RwLock::new(HashMap::new()));
        let pending: PendingMap = Arc::new(RwLock::new(HashMap::new()));
        let (control, mut control_rx) = mpsc::channel::<Message>(8);
        let id: u128 = 89;
        let (tx, _rx) = mpsc::channel::<Vec<u8>>(1);
        streams.write().await.insert(
            id,
            StreamEntry {
                tx,
                slot: Arc::new(Mutex::new(StreamSlot::default())),
            },
        );
        connections
            .write()
            .await
            .insert(id, ConnectionInfo { kind: "tcp".into() });
        route_agent_binary_with_timeout(
            &streams,
            &connections,
            &control,
            &pending,
            id,
            b"first",
            Duration::from_secs(1),
        )
        .await;
        // A local queue that never drains must hit the bounded timeout; only
        // then is the stream closed and the peer notified.
        let _ = tokio::time::timeout(
            Duration::from_secs(2),
            route_agent_binary_with_timeout(
                &streams,
                &connections,
                &control,
                &pending,
                id,
                b"second",
                Duration::from_millis(50),
            ),
        )
        .await
        .expect("routing must return after its bounded timeout");
        assert!(!streams.read().await.contains_key(&id));
        assert!(!connections.read().await.contains_key(&id));
        let message = tokio::time::timeout(Duration::from_secs(1), control_rx.recv())
            .await
            .expect("timeout waiting for StreamClose")
            .expect("control channel closed");
        let Message::Text(text) = message else {
            panic!("expected text control message");
        };
        let Ok(ControlMessage::StreamClose { stream_id, reason }) = decode(text.as_bytes()) else {
            panic!("expected StreamClose");
        };
        assert_eq!(stream_id, "89");
        assert_eq!(reason.as_deref(), Some("local_send_timeout"));
    }

    #[tokio::test]
    async fn udp_route_drops_when_queue_is_full_and_keeps_session() {
        let streams: StreamMap = Arc::new(RwLock::new(HashMap::new()));
        let connections: ConnectionMap = Arc::new(RwLock::new(HashMap::new()));
        let pending: PendingMap = Arc::new(RwLock::new(HashMap::new()));
        let (control, _control_rx) = mpsc::channel::<Message>(8);
        let id: u128 = 90;
        let (tx, mut rx) = mpsc::channel::<Vec<u8>>(1);
        streams.write().await.insert(
            id,
            StreamEntry {
                tx,
                slot: Arc::new(Mutex::new(StreamSlot::default())),
            },
        );
        connections
            .write()
            .await
            .insert(id, ConnectionInfo { kind: "udp".into() });
        route_agent_binary(&streams, &connections, &control, &pending, id, b"first").await;
        // An overflowing UDP datagram is dropped without touching the session.
        route_agent_binary(&streams, &connections, &control, &pending, id, b"dropped").await;
        assert_eq!(rx.recv().await.as_deref(), Some(b"first".as_slice()));
        assert!(
            rx.try_recv().is_err(),
            "overflowing UDP datagram must be dropped"
        );
        assert!(streams.read().await.contains_key(&id));
    }

    #[tokio::test]
    async fn agent_stream_slot_quota_blocks_only_that_stream() {
        let streams: StreamMap = Arc::new(RwLock::new(HashMap::new()));
        let id_a: u128 = 201;
        let id_b: u128 = 202;
        let (tx_a, _rx_a) = mpsc::channel::<Vec<u8>>(8);
        let (tx_b, _rx_b) = mpsc::channel::<Vec<u8>>(8);
        streams.write().await.insert(
            id_a,
            StreamEntry {
                tx: tx_a,
                slot: Arc::new(Mutex::new(StreamSlot::default())),
            },
        );
        streams.write().await.insert(
            id_b,
            StreamEntry {
                tx: tx_b,
                slot: Arc::new(Mutex::new(StreamSlot::default())),
            },
        );
        for _ in 0..STREAM_CHANNEL_QUOTA {
            assert!(acquire_stream_slot_agent(&streams, id_a).await);
        }
        // Stream A is at quota; its next slot must wait...
        let blocked = tokio::spawn({
            let streams = streams.clone();
            async move {
                tokio::time::timeout(
                    Duration::from_millis(100),
                    acquire_stream_slot_agent(&streams, id_a),
                )
                .await
            }
        });
        // ...while stream B can still reserve a slot immediately.
        assert!(acquire_stream_slot_agent(&streams, id_b).await);
        assert!(
            blocked.await.unwrap().is_err(),
            "stream A must stay blocked at quota"
        );
        // Releasing one forwarded frame unblocks A.
        release_stream_slot_agent(&streams, id_a).await;
        let acquired = tokio::time::timeout(
            Duration::from_secs(1),
            acquire_stream_slot_agent(&streams, id_a),
        )
        .await
        .expect("released quota must unblock the stream");
        assert!(acquired);
    }

    #[tokio::test]
    async fn agent_stream_slot_quota_aborts_when_stream_removed() {
        let streams: StreamMap = Arc::new(RwLock::new(HashMap::new()));
        let connections: ConnectionMap = Arc::new(RwLock::new(HashMap::new()));
        let id: u128 = 203;
        let (tx, _rx) = mpsc::channel::<Vec<u8>>(8);
        streams.write().await.insert(
            id,
            StreamEntry {
                tx,
                slot: Arc::new(Mutex::new(StreamSlot::default())),
            },
        );
        for _ in 0..STREAM_CHANNEL_QUOTA {
            assert!(acquire_stream_slot_agent(&streams, id).await);
        }
        let blocked = tokio::spawn({
            let streams = streams.clone();
            async move {
                tokio::time::timeout(
                    Duration::from_millis(100),
                    acquire_stream_slot_agent(&streams, id),
                )
                .await
            }
        });
        // Removing the stream wakes the waiting bridge and reports failure.
        drop_stream(&streams, &connections, id, "test_removed").await;
        let result = tokio::time::timeout(Duration::from_secs(1), blocked)
            .await
            .expect("blocked task must finish after stream removal")
            .expect("acquire must return after stream removal");
        assert_eq!(result, Ok(false));
    }

    #[tokio::test]
    async fn data_channel_task_counts_bytes_in_both_directions() {
        let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
        let addr = listener.local_addr().unwrap();
        let server = tokio::spawn(async move {
            let (stream, _) = listener.accept().await.unwrap();
            let websocket = tokio_tungstenite::accept_async(stream).await.unwrap();
            let (mut sink, mut source) = websocket.split();
            // Answer the DataBind with channel id 1, then push a 100-byte
            // frame down to the agent and expect a 200-byte frame back.
            let first = source.next().await.unwrap().unwrap();
            let Message::Text(text) = first else {
                panic!("expected DataBind text");
            };
            assert!(matches!(
                decode(text.as_bytes()),
                Ok(ControlMessage::DataBind { .. })
            ));
            let bound = encode(&ControlMessage::DataBound { channel_id: 1 }).unwrap();
            sink.send(Message::Text(String::from_utf8(bound).unwrap().into()))
                .await
                .unwrap();
            let down = encode_stream_data(7, &vec![0xAB; 100]).unwrap();
            sink.send(Message::Binary(down.into())).await.unwrap();
            let up = source.next().await.unwrap().unwrap();
            let Message::Binary(bytes) = up else {
                panic!("expected binary frame from agent");
            };
            let (id, data) = decode_stream_data(&bytes).unwrap();
            assert_eq!(id, 7);
            assert_eq!(data.len(), 200);
        });

        let config = AgentConfig {
            server: format!("ws://{addr}/control"),
            data_server: format!("ws://{addr}/data"),
            token: "test-token".into(),
            name: "test".into(),
            data_channels: 2,
            heartbeat_secs: 10,
            pong_timeout_secs: 25,
            reconnect_min_secs: 1,
            reconnect_max_secs: 10,
            log_level: "info".into(),
        };
        let status = AgentStatus::new(&config);
        let streams: StreamMap = Arc::new(RwLock::new(HashMap::new()));
        let connections: ConnectionMap = Arc::new(RwLock::new(HashMap::new()));
        let (control, _control_rx) = mpsc::channel::<Message>(64);
        let pending: PendingMap = Arc::new(RwLock::new(HashMap::new()));
        let task = tokio::spawn(data_channel_task(
            config,
            status.clone(),
            streams,
            connections,
            control,
            pending,
        ));

        // Wait until the channel binds and the down frame was counted.
        let counters = tokio::time::timeout(Duration::from_secs(5), async {
            loop {
                if let Some(counters) = status.traffic.channels.read().await.get(&1).cloned() {
                    if counters.connected.load(Ordering::Relaxed) {
                        return counters;
                    }
                }
                tokio::time::sleep(Duration::from_millis(20)).await;
            }
        })
        .await
        .expect("data channel must bind");
        tokio::time::timeout(Duration::from_secs(5), async {
            while counters.down_bytes.load(Ordering::Relaxed) != 100 {
                tokio::time::sleep(Duration::from_millis(20)).await;
            }
        })
        .await
        .expect("down bytes must be counted");

        // Send a 200-byte frame up through the channel sender.
        let up_frame = encode_stream_data(7, &vec![0xCC; 200]).unwrap();
        status
            .data_channels
            .read()
            .await
            .get(&1)
            .expect("channel sender must exist")
            .send(Message::Binary(up_frame.into()))
            .await
            .unwrap();
        tokio::time::timeout(Duration::from_secs(5), async {
            while counters.up_bytes.load(Ordering::Relaxed) != 200 {
                tokio::time::sleep(Duration::from_millis(20)).await;
            }
        })
        .await
        .expect("up bytes must be counted");

        server.await.unwrap();
        // Once the server drops the socket, the channel task must mark the
        // channel offline while keeping its totals.
        tokio::time::timeout(Duration::from_secs(5), async {
            while counters.connected.load(Ordering::Relaxed) {
                tokio::time::sleep(Duration::from_millis(20)).await;
            }
        })
        .await
        .expect("channel must be marked offline after drop");
        assert_eq!(counters.up_bytes.load(Ordering::Relaxed), 200);
        assert_eq!(counters.down_bytes.load(Ordering::Relaxed), 100);
        task.abort();
    }

    #[tokio::test]
    async fn pending_buffer_grows_past_byte_budget_without_dropping() {
        let pending: PendingMap = Arc::new(RwLock::new(HashMap::new()));
        let id: u128 = 91;
        for _ in 0..10 {
            buffer_pending_frame(&pending, id, &[0xAB; 4], 16, usize::MAX).await;
        }
        let (_, frames, total) = pending
            .read()
            .await
            .get(&id)
            .cloned()
            .expect("pending entry must exist");
        assert_eq!(
            frames.len(),
            10,
            "no frame may be dropped before StreamOpen"
        );
        assert_eq!(total, 40, "buffered byte count must be exact");
        assert!(frames.iter().all(|frame| frame == &vec![0xAB; 4]));
    }

    #[derive(Clone)]
    struct CaptureWriter(Arc<std::sync::Mutex<Vec<u8>>>);

    impl std::io::Write for CaptureWriter {
        fn write(&mut self, buf: &[u8]) -> std::io::Result<usize> {
            self.0.lock().unwrap().extend_from_slice(buf);
            Ok(buf.len())
        }

        fn flush(&mut self) -> std::io::Result<()> {
            Ok(())
        }
    }

    impl<'a> tracing_subscriber::fmt::MakeWriter<'a> for CaptureWriter {
        type Writer = CaptureWriter;

        fn make_writer(&self) -> Self::Writer {
            self.clone()
        }
    }

    #[tokio::test]
    async fn pending_buffer_stops_growing_at_hard_limit() {
        let captured: Arc<std::sync::Mutex<Vec<u8>>> = Arc::new(std::sync::Mutex::new(Vec::new()));
        let writer = CaptureWriter(captured.clone());
        let subscriber = tracing_subscriber::fmt()
            .with_max_level(tracing::Level::ERROR)
            .with_writer(writer)
            .finish();
        let _guard = tracing::subscriber::set_default(subscriber);
        let pending: PendingMap = Arc::new(RwLock::new(HashMap::new()));
        let id: u128 = 92;
        let hard_limit = 16;
        for _ in 0..10 {
            buffer_pending_frame(&pending, id, &[0xAB; 4], 16, hard_limit).await;
        }
        let (_, frames, total) = pending
            .read()
            .await
            .get(&id)
            .cloned()
            .expect("pending entry must exist");
        assert_eq!(frames.len(), 4, "buffer must stop at the hard limit");
        assert_eq!(
            total, hard_limit,
            "buffered byte count must cap at the limit"
        );
        // Frames past the ceiling keep being dropped.
        buffer_pending_frame(&pending, id, &[0xAB; 4], 16, hard_limit).await;
        assert_eq!(
            pending.read().await.get(&id).unwrap().2,
            hard_limit,
            "buffer must not grow past the hard limit"
        );
        drop(_guard);
        let captured = captured.lock().unwrap();
        let output = String::from_utf8_lossy(&captured);
        assert!(
            output.contains("hit hard limit"),
            "expected an error log for dropped frames, got: {output}"
        );
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
    fn data_channel_backoff_grows_and_stays_bounded() {
        for _ in 0..50 {
            let first = data_channel_backoff(0);
            let second = data_channel_backoff(1);
            assert!(
                (0.7 - 1e-9..=1.3 + 1e-9).contains(&first.as_secs_f64()),
                "first backoff out of jitter range"
            );
            assert!(
                (1.4 - 1e-9..=2.6 + 1e-9).contains(&second.as_secs_f64()),
                "second backoff out of jitter range"
            );
            let capped = data_channel_backoff(20);
            assert!(
                capped.as_secs_f64() <= 60.0 * 1.3 + 1e-9,
                "backoff must stay bounded"
            );
        }
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

    #[test]
    fn server_url_validation_accepts_ws_and_wss_only() {
        assert!(validate_server_url("ws://123.207.8.77:18080/control"));
        assert!(validate_server_url("wss://tunnel.example.com/control"));
        assert!(!validate_server_url("http://example.com"));
        assert!(!validate_server_url(""));
        assert!(!validate_server_url("tcp://example.com"));
    }

    #[test]
    fn pid_file_parsing_accepts_digits_only() {
        assert_eq!(parse_pid_file("12345\n"), Some(12345));
        assert_eq!(parse_pid_file(" 42 "), Some(42));
        assert_eq!(parse_pid_file(""), None);
        assert_eq!(parse_pid_file("abc"), None);
        assert_eq!(parse_pid_file("12x"), None);
    }

    #[test]
    fn win_arg_quoting_matches_shell_parsing() {
        assert_eq!(quote_win_arg("abc"), "abc");
        assert_eq!(quote_win_arg(""), "\"\"");
        assert_eq!(quote_win_arg("a b"), "\"a b\"");
        assert_eq!(quote_win_arg("a\"b"), "\"a\\\"b\"");
        assert_eq!(quote_win_arg("--server"), "--server");
    }

    #[test]
    fn settings_reconnect_ignores_empty_server_url() {
        let current = AgentSettings {
            device_name: "pc".into(),
            server_url: "ws://123.207.8.77:18080/control".into(),
            data_channels: 2,
            heartbeat_secs: 10,
            pong_timeout_secs: 25,
            reconnect_min_secs: 1,
            reconnect_max_secs: 10,
            log_level: "info".into(),
        };
        // The server default sends an empty server_url; it must NOT force a
        // reconnect that would wipe the local bootstrap address.
        let incoming = AgentSettings {
            server_url: String::new(),
            ..current.clone()
        };
        assert!(!settings_reconnect_decision(&current, &incoming));
        // A real address change and a data-channels change still reconnect.
        let moved = AgentSettings {
            server_url: "ws://other.example.com/control".into(),
            ..current.clone()
        };
        assert!(settings_reconnect_decision(&current, &moved));
        let more_channels = AgentSettings {
            data_channels: 4,
            ..current.clone()
        };
        assert!(settings_reconnect_decision(&current, &more_channels));
    }

    #[test]
    fn format_bytes_uses_adaptive_units() {
        assert_eq!(format_bytes(0), "0 B");
        assert_eq!(format_bytes(1023), "1023 B");
        assert_eq!(format_bytes(1024), "1 KB");
        assert_eq!(format_bytes(1536), "1.5 KB");
        assert_eq!(format_bytes(1_048_576), "1 MB");
        assert_eq!(format_bytes(1_073_741_824), "1 GB");
        assert_eq!(format_bytes(1_099_511_627_776), "1 TB");
    }

    #[tokio::test]
    async fn traffic_stats_accumulate_across_channel_reconnects() {
        let stats = TrafficStats::default();
        let counters = {
            let mut map = stats.channels.write().await;
            map.entry(1)
                .or_insert_with(|| Arc::new(ChannelCounters::default()))
                .clone()
        };
        counters.connected.store(true, Ordering::Relaxed);
        counters.up_bytes.fetch_add(1000, Ordering::Relaxed);
        counters.down_bytes.fetch_add(500, Ordering::Relaxed);
        // Simulate a channel drop and a rebind on the same channel id; the
        // totals must carry over instead of resetting.
        counters.connected.store(false, Ordering::Relaxed);
        let rebound = {
            let mut map = stats.channels.write().await;
            map.entry(1)
                .or_insert_with(|| Arc::new(ChannelCounters::default()))
                .clone()
        };
        rebound.connected.store(true, Ordering::Relaxed);
        rebound.up_bytes.fetch_add(24, Ordering::Relaxed);
        assert_eq!(rebound.up_bytes.load(Ordering::Relaxed), 1024);
        assert_eq!(rebound.down_bytes.load(Ordering::Relaxed), 500);
        assert!(rebound.connected.load(Ordering::Relaxed));
    }

    #[tokio::test]
    async fn ipc_snapshot_serializes_and_totals() {
        let config = AgentConfig {
            server: "ws://127.0.0.1:18080/control".into(),
            data_server: "ws://127.0.0.1:18080/data".into(),
            token: String::new(),
            name: "test".into(),
            data_channels: 2,
            heartbeat_secs: 10,
            pong_timeout_secs: 25,
            reconnect_min_secs: 1,
            reconnect_max_secs: 10,
            log_level: "info".into(),
        };
        let status = AgentStatus::new(&config);
        let counters = Arc::new(ChannelCounters::default());
        counters.up_bytes.store(1000, Ordering::Relaxed);
        counters.down_bytes.store(24, Ordering::Relaxed);
        counters.connected.store(true, Ordering::Relaxed);
        status.traffic.channels.write().await.insert(1, counters);
        *status.settings_synced_at.lock().unwrap() = Some(1_752_000_000);

        let snapshot = build_ipc_snapshot(&status).await;
        assert_eq!(snapshot.settings.device_name, "test");
        assert_eq!(snapshot.settings_synced_at, Some(1_752_000_000));
        assert_eq!(snapshot.channels.len(), 1);
        assert_eq!(snapshot.channels[0].channel_id, 1);
        assert_eq!(snapshot.channels[0].up_bytes, 1000);
        assert_eq!(snapshot.channels[0].down_bytes, 24);
        assert!(snapshot.channels[0].connected);
        assert_eq!(
            snapshot.totals,
            IpcTrafficTotals {
                up_bytes: 1000,
                down_bytes: 24,
                total_bytes: 1024,
            }
        );

        let encoded = serde_json::to_vec(&snapshot).unwrap();
        let decoded: IpcSnapshot = serde_json::from_slice(&encoded).unwrap();
        assert_eq!(decoded, snapshot);
    }

    #[test]
    fn unix_time_formats_epoch() {
        assert!(format_unix_time(0).starts_with("1970-01-01"));
    }
}
