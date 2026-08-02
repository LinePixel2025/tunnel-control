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
        atomic::{AtomicBool, Ordering},
    },
    time::{Duration, Instant, SystemTime},
};
use tokio::{
    io::{AsyncReadExt, AsyncWriteExt},
    net::{TcpListener, TcpStream, UdpSocket},
    sync::{RwLock, mpsc},
};
use tokio_tungstenite::{connect_async, tungstenite::Message};
use tunnel_protocol::{
    ControlMessage, PROTOCOL_VERSION, TunnelKind, TunnelSpec, decode, decode_stream_data, encode,
    encode_stream_data,
};

type StreamMap = Arc<RwLock<HashMap<u128, mpsc::Sender<Vec<u8>>>>>;
type ConnectionMap = Arc<RwLock<HashMap<u128, ConnectionInfo>>>;

/// Shared runtime state exposed to the local GUI through the status server.
#[derive(Clone, Default)]
struct AgentStatus {
    connected: Arc<AtomicBool>,
    specs: Arc<RwLock<HashMap<String, TunnelSpec>>>,
    connections: ConnectionMap,
}

#[derive(Clone)]
struct ConnectionInfo {
    stream_id: String,
    tunnel_id: String,
    kind: String,
    public_port: u16,
    local_host: String,
    local_port: u16,
    opened_at: u64,
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
                "opened_at": connection.opened_at,
            })
        })
        .collect();
    serde_json::json!({
        "connected": connected,
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
    let file_config = load_file_config();
    let server = env::var("TUNNEL_SERVER_URL")
        .ok()
        .or_else(|| file_config.get("TUNNEL_SERVER_URL").cloned())
        .unwrap_or_else(|| "ws://127.0.0.1:18080/control".into());
    let token = env::var("TUNNEL_TOKEN")
        .ok()
        .or_else(|| file_config.get("TUNNEL_TOKEN").cloned())
        .unwrap_or_else(|| "change-me-agent-token".into());
    let name = env::var("COMPUTERNAME").unwrap_or_else(|_| "Windows agent".into());
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
        loop {
            if let Err(error) = run(&server, &token, &name, &status).await {
                tracing::warn!(%error, "agent disconnected; retrying");
            }
            tokio::time::sleep(Duration::from_secs(5)).await;
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

async fn run(
    server: &str,
    token: &str,
    name: &str,
    status: &AgentStatus,
) -> Result<(), Box<dyn std::error::Error>> {
    let (socket, _) = connect_async(server).await?;
    status.connected.store(true, Ordering::Relaxed);
    let (mut write, mut read) = socket.split();
    let (out_tx, mut out_rx) = mpsc::channel::<Message>(256);
    let specs = status.specs.clone();
    let streams: StreamMap = Arc::new(RwLock::new(HashMap::new()));
    let connections = status.connections.clone();
    let last_pong = Arc::new(std::sync::Mutex::new(Instant::now()));

    let register = ControlMessage::Register {
        version: PROTOCOL_VERSION,
        token: token.into(),
        device_name: name.into(),
    };
    out_tx
        .send(Message::Text(String::from_utf8(encode(&register)?)?.into()))
        .await?;
    let writer_task = tokio::spawn(async move {
        while let Some(message) = out_rx.recv().await {
            if write.send(message).await.is_err() {
                break;
            }
        }
    });

    let reader_out = out_tx.clone();
    let reader_specs = specs.clone();
    let reader_streams = streams.clone();
    let reader_connections = connections.clone();
    let reader_pong = last_pong.clone();
    let reader_task = tokio::spawn(async move {
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
                    }
                    Ok(ControlMessage::StreamOpen {
                        stream_id,
                        tunnel_id,
                    }) => {
                        let Ok(id) = stream_id.parse::<u128>() else {
                            continue;
                        };
                        if let Some(spec) = reader_specs.read().await.get(&tunnel_id).cloned() {
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
                                    opened_at,
                                },
                            );
                            let out = reader_out.clone();
                            let streams = reader_streams.clone();
                            let connections = reader_connections.clone();
                            tokio::spawn(async move {
                                match spec.kind {
                                    TunnelKind::Udp => {
                                        bridge_local_udp(id, spec, rx, out, streams, connections)
                                            .await;
                                    }
                                    _ => {
                                        bridge_local(id, spec, rx, out, streams, connections).await
                                    }
                                }
                            });
                        } else {
                            send_close(&reader_out, stream_id, Some("unknown_tunnel".into())).await;
                        }
                    }
                    Ok(ControlMessage::StreamClose { stream_id, .. }) => {
                        if let Ok(id) = stream_id.parse::<u128>() {
                            reader_streams.write().await.remove(&id);
                            reader_connections.write().await.remove(&id);
                        }
                    }
                    _ => {}
                },
                Message::Binary(bytes) => {
                    if let Ok((id, data)) = decode_stream_data(&bytes) {
                        if let Some(tx) = reader_streams.read().await.get(&id).cloned() {
                            let _ = tx.send(data.to_vec()).await;
                        }
                    }
                }
                _ => {}
            }
        }
    });

    loop {
        tokio::time::sleep(Duration::from_secs(15)).await;
        // After wake-from-sleep the TCP connection may be dead while the OS
        // keeps retransmitting; require a fresh pong or reconnect promptly.
        if last_pong.lock().unwrap().elapsed() > Duration::from_secs(45) {
            break;
        }
        let heartbeat = ControlMessage::Heartbeat {
            version: PROTOCOL_VERSION,
            latency_ms: 0,
        };
        if out_tx
            .send(Message::Text(
                String::from_utf8(encode(&heartbeat)?)?.into(),
            ))
            .await
            .is_err()
        {
            break;
        }
        if out_tx.send(Message::Ping(Vec::new().into())).await.is_err() {
            break;
        }
    }
    status.connected.store(false, Ordering::Relaxed);
    status.connections.write().await.clear();
    writer_task.abort();
    reader_task.abort();
    Err("control channel closed; reconnecting".into())
}

async fn bridge_local(
    id: u128,
    spec: TunnelSpec,
    mut rx: mpsc::Receiver<Vec<u8>>,
    out: mpsc::Sender<Message>,
    streams: StreamMap,
    connections: ConnectionMap,
) {
    let Ok(socket) = TcpStream::connect(format!("{}:{}", spec.local_host, spec.local_port)).await
    else {
        streams.write().await.remove(&id);
        connections.write().await.remove(&id);
        send_close(&out, id.to_string(), Some("local_connect_failed".into())).await;
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
                let Ok(frame) = encode_stream_data(id, &buffer[..size]) else {
                    break;
                };
                if out.send(Message::Binary(frame.into())).await.is_err() {
                    break;
                }
            }
        }
    }
    streams.write().await.remove(&id);
    connections.write().await.remove(&id);
    write_task.abort();
    send_close(&out, id.to_string(), None).await;
}

async fn bridge_local_udp(
    id: u128,
    spec: TunnelSpec,
    mut rx: mpsc::Receiver<Vec<u8>>,
    out: mpsc::Sender<Message>,
    streams: StreamMap,
    connections: ConnectionMap,
) {
    let Ok(socket) = UdpSocket::bind("0.0.0.0:0").await else {
        streams.write().await.remove(&id);
        connections.write().await.remove(&id);
        send_close(&out, id.to_string(), Some("local_bind_failed".into())).await;
        return;
    };
    if socket
        .connect(format!("{}:{}", spec.local_host, spec.local_port))
        .await
        .is_err()
    {
        streams.write().await.remove(&id);
        connections.write().await.remove(&id);
        send_close(&out, id.to_string(), Some("local_connect_failed".into())).await;
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
            Ok(0) | Err(_) => break,
            Ok(size) => {
                let Ok(frame) = encode_stream_data(id, &buffer[..size]) else {
                    break;
                };
                if out.send(Message::Binary(frame.into())).await.is_err() {
                    break;
                }
            }
        }
    }
    streams.write().await.remove(&id);
    connections.write().await.remove(&id);
    write_task.abort();
    send_close(&out, id.to_string(), None).await;
}

async fn send_close(out: &mpsc::Sender<Message>, stream_id: String, reason: Option<String>) {
    let close = ControlMessage::StreamClose { stream_id, reason };
    if let Ok(payload) = encode(&close) {
        let _ = out
            .send(Message::Text(
                String::from_utf8_lossy(&payload).into_owned().into(),
            ))
            .await;
    }
}

#[cfg(test)]
mod tests {
    use super::*;

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
        let (out_tx, mut out_rx) = mpsc::channel::<Message>(64);
        let streams: StreamMap = Arc::new(RwLock::new(HashMap::new()));
        let connections: ConnectionMap = Arc::new(RwLock::new(HashMap::new()));
        let (tx, rx) = mpsc::channel::<Vec<u8>>(128);
        // The StreamOpen handler registers the stream before spawning the bridge.
        streams.write().await.insert(42, tx.clone());
        let bridge = tokio::spawn(bridge_local_udp(
            42,
            spec,
            rx,
            out_tx,
            streams.clone(),
            connections.clone(),
        ));

        tx.send(b"hello-udp".to_vec()).await.unwrap();

        let message = tokio::time::timeout(Duration::from_secs(2), out_rx.recv())
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
}
