use futures_util::{SinkExt, StreamExt};
use std::{
    collections::HashMap,
    env,
    ffi::OsString,
    fs,
    io::{self, Write},
    path::PathBuf,
    process::Command,
    sync::{
        Arc,
        atomic::{AtomicBool, AtomicU64, Ordering},
    },
    time::{Duration, Instant, SystemTime},
};
use tokio::{
    io::{AsyncReadExt, AsyncWriteExt},
    net::{TcpListener, TcpStream, UdpSocket},
    sync::{Mutex, RwLock, mpsc},
};
use tokio_tungstenite::{connect_async, tungstenite::Message};
use tunnel_protocol::{
    ControlMessage, PROTOCOL_VERSION, TunnelKind, TunnelSpec, decode, decode_stream_data, encode,
    encode_stream_data,
};
use url::Url;

type StreamMap = Arc<RwLock<HashMap<u128, mpsc::Sender<Vec<u8>>>>>;
type ConnectionMap = Arc<RwLock<HashMap<u128, ConnectionInfo>>>;
type DataSenderMap = Arc<RwLock<HashMap<u16, mpsc::Sender<Message>>>>;
type TaskMap = Arc<tokio::sync::Mutex<HashMap<u128, tokio::task::JoinHandle<()>>>>;

/// Shared runtime state exposed to the local GUI through the status server.
#[derive(Clone, Default)]
struct AgentStatus {
    connected: Arc<AtomicBool>,
    specs: Arc<RwLock<HashMap<String, TunnelSpec>>>,
    connections: ConnectionMap,
    data_channels: DataSenderMap,
    bandwidth: BandwidthLimiter,
}

#[derive(Clone)]
struct ConnectionInfo {
    stream_id: String,
    tunnel_id: String,
    kind: String,
    public_port: u16,
    local_host: String,
    local_port: u16,
    data_channel: u16,
    opened_at: u64,
}

/// Connection parameters for one agent run. Values come from environment
/// variables with safe defaults, so recovery timing is tunable per deploy.
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
}

impl AgentConfig {
    fn from_env() -> Self {
        let server = env::var("TUNNEL_SERVER_URL")
            .ok()
            .or_else(|| load_file_config().get("TUNNEL_SERVER_URL").cloned())
            .unwrap_or_else(|| "ws://127.0.0.1:18080/control".into());
        let token = env::var("TUNNEL_TOKEN")
            .ok()
            .or_else(|| load_file_config().get("TUNNEL_TOKEN").cloned())
            .unwrap_or_else(|| "change-me-agent-token".into());
        let name = env::var("COMPUTERNAME").unwrap_or_else(|_| "Windows agent".into());
        let data_server = Url::parse(&server)
            .map(|mut url| {
                url.set_path("/data");
                url.to_string()
            })
            .unwrap_or_else(|_| format!("{}/data", server.trim_end_matches('/')));
        let data_channels = env::var("DATA_CHANNELS")
            .ok()
            .and_then(|value| value.parse().ok())
            .filter(|channels| (1..=8).contains(channels))
            .unwrap_or(2);
        let heartbeat_secs = env_secs("AGENT_HEARTBEAT_SECS", 10, 3, 60);
        let pong_timeout_secs = env_secs("AGENT_PONG_TIMEOUT_SECS", 25, 5, 300);
        let reconnect_min_secs = env_secs("AGENT_RECONNECT_MIN_SECS", 1, 1, 60);
        let reconnect_max_secs =
            env_secs("AGENT_RECONNECT_MAX_SECS", 10, 1, 300).max(reconnect_min_secs);
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
        }
    }
}

fn env_secs(key: &str, default: u64, min: u64, max: u64) -> u64 {
    env::var(key)
        .ok()
        .and_then(|value| value.parse().ok())
        .filter(|secs| *secs >= min && *secs <= max)
        .unwrap_or(default)
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

/// Serves `GET http://127.0.0.1:17890/status` for the local GUI. The service
/// binds only to loopback and exposes no secrets, so a plain CORS-enabled
/// JSON endpoint is sufficient.
async fn status_server(status: AgentStatus) {
    let Ok(listener) = TcpListener::bind("127.0.0.1:17890").await else {
        tracing::warn!("local status server could not bind 127.0.0.1:17890");
        return;
    };
    loop {
        let Ok((socket, _)) = listener.accept().await else {
            continue;
        };
        let status = status.clone();
        tokio::spawn(async move {
            handle_status_request(socket, status).await;
        });
    }
}

async fn handle_status_request(mut socket: TcpStream, status: AgentStatus) {
    let mut buffer = [0_u8; 1024];
    let Ok(size) = socket.read(&mut buffer).await else {
        return;
    };
    let request = String::from_utf8_lossy(&buffer[..size]);
    let path = request.split_whitespace().nth(1).unwrap_or("/");
    let (code, body) = if path == "/status" {
        ("200 OK", build_status_json(&status).await)
    } else {
        ("404 Not Found", r#"{"error":"not found"}"#.to_string())
    };
    let response = format!(
        "HTTP/1.1 {code}\r\nContent-Type: application/json\r\nAccess-Control-Allow-Origin: *\r\nCache-Control: no-store\r\nContent-Length: {}\r\nConnection: close\r\n\r\n{body}",
        body.len()
    );
    let _ = socket.write_all(response.as_bytes()).await;
}

async fn build_status_json(status: &AgentStatus) -> String {
    let connected = status.connected.load(Ordering::Relaxed);
    let tunnels: Vec<serde_json::Value> = status
        .specs
        .read()
        .await
        .values()
        .map(|tunnel| {
            serde_json::json!({
                "id": tunnel.id,
                "name": tunnel.name,
                "kind": kind_str(&tunnel.kind),
                "public_port": tunnel.public_port,
                "local_host": tunnel.local_host,
                "local_port": tunnel.local_port,
                "enabled": tunnel.enabled,
                "max_connections": tunnel.max_connections,
            })
        })
        .collect();
    let connections: Vec<serde_json::Value> = status
        .connections
        .read()
        .await
        .values()
        .map(|connection| {
            serde_json::json!({
                "stream_id": connection.stream_id,
                "tunnel_id": connection.tunnel_id,
                "kind": connection.kind,
                "public_port": connection.public_port,
                "local_host": connection.local_host,
                "local_port": connection.local_port,
                "data_channel": connection.data_channel,
                "opened_at": connection.opened_at,
            })
        })
        .collect();
    let data_channels: Vec<u16> = {
        let mut channels: Vec<u16> = status.data_channels.read().await.keys().copied().collect();
        channels.sort_unstable();
        channels
    };
    serde_json::json!({
        "connected": connected,
        "data_channels": data_channels,
        "tunnels": tunnels,
        "connections": connections,
    })
    .to_string()
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
    tracing_subscriber::fmt().init();
    let arguments: Vec<String> = env::args().collect();
    if arguments.iter().any(|argument| argument == "--service") {
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
    if !arguments.iter().any(|argument| argument == "--agent") {
        if let Err(error) = install_service() {
            eprintln!("Installation failed: {error}");
            std::process::exit(1);
        }
        return;
    }
    run_agent_forever();
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
    let config = AgentConfig::from_env();
    let runtime = tokio::runtime::Builder::new_multi_thread()
        .enable_all()
        .build()
        .expect("failed to build tokio runtime");
    runtime.block_on(async move {
        let status = AgentStatus::default();
        let status_server_status = status.clone();
        tokio::spawn(async move {
            status_server(status_server_status).await;
        });
        let mut attempt = 0_u32;
        let mut jitter = 0_u64;
        loop {
            if let Err(error) = run(&config, &status).await {
                tracing::warn!(%error, "agent disconnected; retrying");
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

fn install_service() -> Result<(), Box<dyn std::error::Error>> {
    #[cfg(not(windows))]
    return Err("The installer is only supported on Windows".into());

    #[cfg(windows)]
    {
        let mut server_url = String::new();
        let mut token = String::new();
        print!("Server WebSocket URL (example: ws://203.0.113.10:18080/control): ");
        io::stdout().flush()?;
        io::stdin().read_line(&mut server_url)?;
        print!("Device token: ");
        io::stdout().flush()?;
        io::stdin().read_line(&mut token)?;
        let server_url = server_url.trim();
        let token = token.trim();
        if server_url.is_empty() || token.is_empty() {
            return Err("Server URL and device token are required".into());
        }
        let install_root = PathBuf::from(env::var("ProgramFiles")?).join("TunnelControl");
        fs::create_dir_all(&install_root)?;
        let agent_path = install_root.join("tunnel-agent.exe");
        fs::copy(env::current_exe()?, &agent_path)?;
        fs::write(
            install_root.join("agent.env"),
            format!("TUNNEL_SERVER_URL={server_url}\nTUNNEL_TOKEN={token}\n"),
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

async fn run(config: &AgentConfig, status: &AgentStatus) -> Result<(), Box<dyn std::error::Error>> {
    let (socket, _) = connect_async(&config.server).await?;
    enable_tcp_keepalive(&socket);
    status.connected.store(true, Ordering::Relaxed);
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
    let bridge_tasks: TaskMap = Arc::new(tokio::sync::Mutex::new(HashMap::new()));
    let data_tasks: Arc<tokio::sync::Mutex<Vec<tokio::task::JoinHandle<()>>>> =
        Arc::new(tokio::sync::Mutex::new(Vec::new()));
    let last_pong = Arc::new(std::sync::Mutex::new(Instant::now()));
    let reader_done = Arc::new(tokio::sync::Notify::new());

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
    let reader_pong = last_pong.clone();
    let reader_config = config.clone();
    let reader_status = status.clone();
    let reader_data_tasks = data_tasks.clone();
    let reader_done_notify = reader_done.clone();
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
                                ));
                                reader_data_tasks.lock().await.push(task);
                            }
                        }
                    }
                    Ok(ControlMessage::BandwidthConfig { mbps }) => {
                        reader_bandwidth.set_mbps(mbps);
                        tracing::info!(mbps, "server bandwidth limit applied");
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
                        reader_streams.write().await.insert(id, tx);
                        let opened_at = SystemTime::now()
                            .duration_since(SystemTime::UNIX_EPOCH)
                            .map(|duration| duration.as_secs())
                            .unwrap_or(0);
                        reader_connections.write().await.insert(
                            id,
                            ConnectionInfo {
                                stream_id: id.to_string(),
                                tunnel_id: tunnel_id.clone(),
                                kind: kind_str(&spec.kind).to_string(),
                                public_port: spec.public_port,
                                local_host: spec.local_host.clone(),
                                local_port: spec.local_port,
                                data_channel,
                                opened_at,
                            },
                        );
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
                    Ok(ControlMessage::StreamClose { stream_id, .. }) => {
                        if let Ok(id) = stream_id.parse::<u128>() {
                            reader_streams.write().await.remove(&id);
                            reader_connections.write().await.remove(&id);
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

    loop {
        tokio::select! {
            _ = tokio::time::sleep(Duration::from_secs(config.heartbeat_secs)) => {}
            _ = reader_done.notified() => break,
        }
        // After wake-from-sleep the TCP connection may be dead while the OS
        // keeps retransmitting; require a fresh pong or reconnect promptly.
        if last_pong.lock().unwrap().elapsed() > Duration::from_secs(config.pong_timeout_secs) {
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
    status.connected.store(false, Ordering::Relaxed);
    status.connections.write().await.clear();
    for task in data_tasks.lock().await.drain(..) {
        task.abort();
    }
    for (_, task) in bridge_tasks.lock().await.drain() {
        task.abort();
    }
    streams.write().await.clear();
    data_channels.write().await.clear();
    writer_task.abort();
    reader_task.abort();
    Err("control channel closed; reconnecting".into())
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
                status.data_channels.write().await.insert(channel_id, tx);
                let writer = tokio::spawn(async move {
                    while let Some(message) = rx.recv().await {
                        if sink.send(message).await.is_err() {
                            break;
                        }
                    }
                });
                let reader_streams = streams.clone();
                let reader_connections = connections.clone();
                let reader_control = control.clone();
                while let Some(Ok(message)) = source.next().await {
                    if let Message::Binary(bytes) = message {
                        if let Ok((id, data)) = decode_stream_data(&bytes) {
                            route_agent_binary(
                                &reader_streams,
                                &reader_connections,
                                &reader_control,
                                id,
                                data,
                            )
                            .await;
                        }
                    }
                }
                writer.abort();
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
    id: u128,
    data: &[u8],
) {
    let tx = {
        let map = streams.read().await;
        map.get(&id).cloned()
    };
    let Some(tx) = tx else {
        return;
    };
    if tx.try_send(data.to_vec()).is_ok() {
        return;
    }
    let is_udp = connections
        .read()
        .await
        .get(&id)
        .map(|connection| connection.kind == "udp")
        .unwrap_or(false);
    if is_udp {
        // UDP tolerates loss; drop the datagram and keep the session alive.
        return;
    }
    // Never block a data channel on one saturated TCP stream; close it so the
    // client can reconnect.
    streams.write().await.remove(&id);
    connections.write().await.remove(&id);
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
        streams.write().await.remove(&id);
        connections.write().await.remove(&id);
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
    streams.write().await.remove(&id);
    connections.write().await.remove(&id);
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
        streams.write().await.remove(&id);
        connections.write().await.remove(&id);
        send_close(&control, id.to_string(), Some("local_bind_failed".into()));
        return;
    };
    if socket
        .connect(format!("{}:{}", spec.local_host, spec.local_port))
        .await
        .is_err()
    {
        streams.write().await.remove(&id);
        connections.write().await.remove(&id);
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
    streams.write().await.remove(&id);
    connections.write().await.remove(&id);
    write_task.abort();
    send_close(&control, id.to_string(), None);
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
}
