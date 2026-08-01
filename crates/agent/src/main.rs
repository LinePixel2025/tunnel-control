use futures_util::{SinkExt, StreamExt};
use std::{collections::HashMap, env, sync::Arc, time::Duration};
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

#[tokio::main]
async fn main() {
    tracing_subscriber::fmt().init();
    let server =
        env::var("TUNNEL_SERVER_URL").unwrap_or_else(|_| "ws://127.0.0.1:18080/control".into());
    let token = env::var("TUNNEL_TOKEN").unwrap_or_else(|_| "change-me-agent-token".into());
    let name = env::var("COMPUTERNAME").unwrap_or_else(|_| "Windows agent".into());
    loop {
        if let Err(error) = run(&server, &token, &name).await {
            tracing::warn!(%error, "agent disconnected; retrying");
        }
        tokio::time::sleep(Duration::from_secs(5)).await;
    }
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
