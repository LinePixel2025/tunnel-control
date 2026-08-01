use futures_util::{SinkExt, StreamExt};
use std::{
    collections::HashMap,
    env, fs,
    ffi::OsString,
    io::{self, Write},
    path::PathBuf,
    process::Command,
    sync::Arc,
    time::Duration,
};
use tokio::{
    io::{AsyncReadExt, AsyncWriteExt},
    net::TcpStream,
    sync::{RwLock, mpsc},
};
use tokio_tungstenite::{connect_async, tungstenite::Message};
use tunnel_protocol::{
    ControlMessage, PROTOCOL_VERSION, TunnelSpec, decode, decode_stream_data, encode,
    encode_stream_data,
};

type StreamMap = Arc<RwLock<HashMap<u128, mpsc::Sender<Vec<u8>>>>>;

#[cfg(windows)]
use windows_service::{
    define_windows_service,
    service::{ServiceControl, ServiceControlAccept, ServiceExitCode, ServiceState, ServiceStatus, ServiceType},
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
            if let Err(error) = windows_service::service_dispatcher::start("TunnelAgent", ffi_service_main) {
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
        loop {
            if let Err(error) = run(&server, &token, &name).await {
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

async fn run(server: &str, token: &str, name: &str) -> Result<(), Box<dyn std::error::Error>> {
    let (socket, _) = connect_async(server).await?;
    let (mut write, mut read) = socket.split();
    let (out_tx, mut out_rx) = mpsc::channel::<Message>(256);
    let specs = Arc::new(RwLock::new(HashMap::<String, TunnelSpec>::new()));
    let streams: StreamMap = Arc::new(RwLock::new(HashMap::new()));

    let register = ControlMessage::Register {
        version: PROTOCOL_VERSION,
        token: token.into(),
        device_name: name.into(),
    };
    out_tx
        .send(Message::Text(String::from_utf8(encode(&register)?)?.into()))
        .await?;
    tokio::spawn(async move {
        while let Some(message) = out_rx.recv().await {
            if write.send(message).await.is_err() {
                break;
            }
        }
    });

    let reader_out = out_tx.clone();
    let reader_specs = specs.clone();
    let reader_streams = streams.clone();
    tokio::spawn(async move {
        while let Some(Ok(message)) = read.next().await {
            match message {
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
                            tokio::spawn(bridge_local(
                                id,
                                spec,
                                reader_out.clone(),
                                reader_streams.clone(),
                            ));
                        } else {
                            send_close(&reader_out, stream_id, Some("unknown_tunnel".into())).await;
                        }
                    }
                    Ok(ControlMessage::StreamClose { stream_id, .. }) => {
                        if let Ok(id) = stream_id.parse::<u128>() {
                            reader_streams.write().await.remove(&id);
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
        let heartbeat = ControlMessage::Heartbeat {
            version: PROTOCOL_VERSION,
            latency_ms: 0,
        };
        out_tx
            .send(Message::Text(
                String::from_utf8(encode(&heartbeat)?)?.into(),
            ))
            .await?;
    }
}

async fn bridge_local(id: u128, spec: TunnelSpec, out: mpsc::Sender<Message>, streams: StreamMap) {
    let Ok(socket) = TcpStream::connect(format!("{}:{}", spec.local_host, spec.local_port)).await
    else {
        send_close(&out, id.to_string(), Some("local_connect_failed".into())).await;
        return;
    };
    let (mut reader, mut writer) = socket.into_split();
    let (tx, mut rx) = mpsc::channel::<Vec<u8>>(128);
    streams.write().await.insert(id, tx);
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
