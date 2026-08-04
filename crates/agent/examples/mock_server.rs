//! Local mock control server for verifying the agent's connection behavior
//! without a full Docker stack (Postgres/Redis/admin).
//!
//! Accepts any `Register`, replies with `Registered` + `BandwidthConfig` +
//! `SettingsSync` carrying an EMPTY server_url (the server default), then
//! keeps the socket open and prints every message it receives. If the agent
//! handles the empty server_url correctly it stays connected and keeps
//! sending heartbeats; before the fix it disconnected and reconnected to the
//! wrong address.
//!
//! Run:  cargo run -p tunnel-agent --example mock_server

use futures_util::{SinkExt, StreamExt};
use tokio::net::TcpListener;
use tokio_tungstenite::accept_async;
use tokio_tungstenite::tungstenite::Message;
use tunnel_protocol::{AgentSettings, ControlMessage, decode, encode};

#[tokio::main]
async fn main() {
    let listener = TcpListener::bind("127.0.0.1:18081")
        .await
        .expect("bind 127.0.0.1:18081");
    println!("mock control server listening on ws://127.0.0.1:18081/control");
    loop {
        let (stream, _peer) = listener.accept().await.expect("accept");
        tokio::spawn(async move {
            let websocket = accept_async(stream).await.expect("websocket handshake");
            let (mut sink, mut source) = websocket.split();
            // Data WebSockets open with DataBind; answer once with DataBound
            // so the agent binds the channel and traffic counters show up.
            let mut data_bound = false;
            while let Some(Ok(message)) = source.next().await {
                match message {
                    Message::Text(text) => {
                        println!("server received: {text}");
                        if !data_bound
                            && matches!(
                                decode(text.as_bytes()),
                                Ok(ControlMessage::DataBind { .. })
                            )
                        {
                            data_bound = true;
                            if let Ok(payload) =
                                encode(&ControlMessage::DataBound { channel_id: 1 })
                            {
                                let _ = sink
                                    .send(Message::Text(
                                        String::from_utf8_lossy(&payload).into_owned().into(),
                                    ))
                                    .await;
                            }
                            continue;
                        }
                        // Reply with the same messages a real server sends on
                        // registration, using the default (empty) server_url.
                        for control in [
                            ControlMessage::Registered {
                                device_id: "mock-device".into(),
                                tunnels: Vec::new(),
                            },
                            ControlMessage::BandwidthConfig { mbps: 3 },
                            ControlMessage::SettingsSync {
                                settings: AgentSettings {
                                    device_name: "mock-pc".into(),
                                    server_url: String::new(),
                                    data_channels: 2,
                                    heartbeat_secs: 10,
                                    pong_timeout_secs: 25,
                                    reconnect_min_secs: 1,
                                    reconnect_max_secs: 10,
                                    log_level: "info".into(),
                                },
                            },
                        ] {
                            if let Ok(payload) = encode(&control) {
                                if sink
                                    .send(Message::Text(
                                        String::from_utf8_lossy(&payload).into_owned().into(),
                                    ))
                                    .await
                                    .is_err()
                                {
                                    return;
                                }
                            }
                        }
                    }
                    Message::Binary(bytes) => {
                        println!("server received binary frame: {} bytes", bytes.len());
                    }
                    _ => {}
                }
            }
            println!("server: connection closed by agent");
        });
    }
}
