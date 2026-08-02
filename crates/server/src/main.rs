use argon2::PasswordHasher;
use axum::{
    Json, Router,
    extract::{
        Path, Query, State,
        ws::{Message, WebSocket, WebSocketUpgrade},
    },
    http::{HeaderMap, StatusCode, header},
    response::IntoResponse,
    routing::{get, post, put},
};
use chrono::{Duration, Utc};
use futures_util::{SinkExt, StreamExt};
use jsonwebtoken::{
    DecodingKey, EncodingKey, Header, Validation, decode as jwt_decode, encode as jwt_encode,
};
use rand_core::RngCore;
use redis::AsyncCommands;
use serde::{Deserialize, Serialize};
use sha2::Digest;
use sqlx::{FromRow, PgPool, postgres::PgPoolOptions};
use std::{
    collections::HashMap,
    env,
    net::SocketAddr,
    sync::{
        Arc,
        atomic::{AtomicU64, Ordering},
    },
    time::{Duration as StdDuration, Instant},
};
use tokio::{
    io::AsyncWriteExt,
    net::{TcpListener, UdpSocket},
    sync::{Mutex, RwLock, mpsc, oneshot},
};
use tower_http::{cors::CorsLayer, trace::TraceLayer};
use tunnel_protocol::{
    ControlMessage, TunnelKind, TunnelSpec, decode, decode_stream_data, encode, encode_stream_data,
};
use uuid::Uuid;

#[derive(Clone)]
struct AppState {
    db: PgPool,
    redis: redis::Client,
    jwt_secret: Arc<String>,
    admin_token_ttl_hours: i64,
    bootstrap_agent_token_hash: Option<String>,
    listeners: Arc<RwLock<HashMap<Uuid, tokio::task::JoinHandle<()>>>>,
    udp_session_idle_secs: u64,
    probes: Arc<RwLock<HashMap<String, oneshot::Sender<ProbeOutcome>>>>,
    bandwidth: BandwidthLimiter,
    tunnel_port_start: u16,
    tunnel_port_end: u16,
    data_channels_max: u16,
    shutdown_drain_secs: u64,
    accepting: Arc<std::sync::atomic::AtomicBool>,
    plane: DataPlane,
}

/// In-memory data-plane state shared by the control socket and every data
/// socket. Kept separate from AppState so routing and cleanup logic can be
/// unit tested without a database.
#[derive(Clone, Default)]
struct DataPlane {
    sessions: Arc<RwLock<HashMap<Uuid, SessionEntry>>>,
    streams: Arc<RwLock<HashMap<u128, StreamEntry>>>,
    udp_sessions: Arc<RwLock<HashMap<u128, UdpSession>>>,
    data_channels: Arc<RwLock<HashMap<Uuid, HashMap<u16, DataChannel>>>>,
    data_socket_tasks: Arc<Mutex<HashMap<(Uuid, u16), tokio::task::JoinHandle<()>>>>,
}

/// One live control session for a device. The connection id lets a stale
/// control loop (left over from a previous connection) avoid removing the
/// session registered by a newer connection during a fast reconnect.
#[derive(Clone)]
struct SessionEntry {
    connection_id: Uuid,
    tx: mpsc::Sender<Message>,
}

/// A data WebSocket bound to a device's current control session. `tx` is the
/// queue drained by that socket's writer; new streams are assigned to one of
/// these channels by `pick_data_channel`.
#[derive(Clone)]
struct DataChannel {
    connection_id: Uuid,
    tx: mpsc::Sender<Message>,
}

/// A live TCP stream mapped to the data channel it was assigned to.
#[derive(Clone)]
struct StreamEntry {
    device_id: Uuid,
    data_channel: u16,
    tx: mpsc::Sender<Vec<u8>>,
}
/// A live UDP mapping between one public client (peer) and the agent's local
/// service. The socket is shared with the tunnel listener that owns it.
#[derive(Clone)]
struct UdpSession {
    device_id: Uuid,
    connection_id: Uuid,
    tunnel_id: Uuid,
    data_channel: u16,
    peer: SocketAddr,
    outbox: mpsc::Sender<Vec<u8>>,
    last_seen: Instant,
}
/// Result of routing one data frame to its stream or UDP session.
#[derive(Debug, PartialEq, Eq)]
enum RouteOutcome {
    Ok,
    /// UDP queue full; the datagram is dropped (UDP tolerates loss).
    Dropped,
    /// TCP stream queue saturated; the caller must close the stream.
    StreamSaturated(u128),
    /// UDP session outbox was closed; the session entry is gone.
    UdpSessionGone(u128),
}

/// Removes a session entry only when it still belongs to `connection_id`, so a
/// stale control loop can never delete the session of a newer connection.
fn remove_session_if_owned(
    sessions: &mut HashMap<Uuid, SessionEntry>,
    device_id: Uuid,
    connection_id: Uuid,
) -> bool {
    match sessions.get(&device_id) {
        Some(entry) if entry.connection_id == connection_id => {
            sessions.remove(&device_id);
            true
        }
        _ => false,
    }
}

/// Routes one incoming data frame (from any data socket) to its destination.
/// TCP streams are closed when saturated; UDP datagrams are dropped instead.
async fn route_stream_data(plane: &DataPlane, id: u128, data: &[u8]) -> RouteOutcome {
    let outbox = {
        let sessions = plane.udp_sessions.read().await;
        sessions.get(&id).map(|session| session.outbox.clone())
    };
    if let Some(outbox) = outbox {
        match outbox.try_send(data.to_vec()) {
            Ok(()) => {
                if let Some(current) = plane.udp_sessions.write().await.get_mut(&id) {
                    current.last_seen = Instant::now();
                }
                RouteOutcome::Ok
            }
            Err(mpsc::error::TrySendError::Closed(_)) => {
                plane.udp_sessions.write().await.remove(&id);
                RouteOutcome::UdpSessionGone(id)
            }
            Err(mpsc::error::TrySendError::Full(_)) => RouteOutcome::Dropped,
        }
    } else {
        let tx = {
            let streams = plane.streams.read().await;
            streams.get(&id).map(|entry| entry.tx.clone())
        };
        match tx {
            Some(tx) if tx.try_send(data.to_vec()).is_ok() => RouteOutcome::Ok,
            Some(_) => {
                plane.streams.write().await.remove(&id);
                RouteOutcome::StreamSaturated(id)
            }
            None => RouteOutcome::Ok,
        }
    }
}

/// Sends a control message to the device's current session. Returns false when
/// the device is offline or the send failed.
async fn send_control(state: &AppState, device_id: Uuid, message: &ControlMessage) -> bool {
    let Ok(payload) = encode(message) else {
        return false;
    };
    let Some(session) = state.plane.sessions.read().await.get(&device_id).cloned() else {
        return false;
    };
    session
        .tx
        .send(Message::Text(
            String::from_utf8_lossy(&payload).into_owned().into(),
        ))
        .await
        .is_ok()
}

/// Number of live streams currently assigned to one data channel.
async fn data_channel_load(state: &AppState, device_id: Uuid, channel_id: u16) -> usize {
    let streams = state.plane.streams.read().await;
    let udp = state.plane.udp_sessions.read().await;
    streams
        .values()
        .filter(|entry| entry.device_id == device_id && entry.data_channel == channel_id)
        .count()
        + udp
            .values()
            .filter(|session| session.device_id == device_id && session.data_channel == channel_id)
            .count()
}

/// Picks the data channel with the fewest active streams, preferring the
/// lowest channel id on ties. Returns None while the device has no bound
/// channel (for example during a reconnect); callers drop the connection.
async fn pick_data_channel(state: &AppState, device_id: Uuid) -> Option<u16> {
    let channels: Vec<u16> = {
        let pool = state.plane.data_channels.read().await;
        pool.get(&device_id)
            .map(|channels| channels.keys().copied().collect())
            .unwrap_or_default()
    };
    if channels.is_empty() {
        return None;
    }
    let mut best: Option<(usize, u16)> = None;
    for channel_id in channels {
        let load = data_channel_load(state, device_id, channel_id).await;
        if best.map(|(best_load, _)| load < best_load).unwrap_or(true) {
            best = Some((load, channel_id));
        }
    }
    best.map(|(_, channel_id)| channel_id)
}

/// Removes every stream and UDP session assigned to one data channel and
/// returns their ids so the caller can notify the agent. Used when a data
/// socket drops or a control session ends.
async fn close_channel_streams(plane: &DataPlane, device_id: Uuid, channel_id: u16) -> Vec<u128> {
    let tcp: Vec<u128> = plane
        .streams
        .read()
        .await
        .iter()
        .filter(|(_, entry)| entry.device_id == device_id && entry.data_channel == channel_id)
        .map(|(id, _)| *id)
        .collect();
    for id in &tcp {
        plane.streams.write().await.remove(id);
    }
    let udp: Vec<u128> = plane
        .udp_sessions
        .read()
        .await
        .iter()
        .filter(|(_, session)| session.device_id == device_id && session.data_channel == channel_id)
        .map(|(id, _)| *id)
        .collect();
    for id in &udp {
        plane.udp_sessions.write().await.remove(id);
    }
    tcp.into_iter().chain(udp).collect()
}

/// Tears down data channels bound to one control session (by connection id).
/// Channels opened by a newer connection are left untouched.
async fn teardown_device_data_channels(state: &AppState, device_id: Uuid, connection_id: Uuid) {
    let channels: Vec<u16> = {
        let pool = state.plane.data_channels.read().await;
        pool.get(&device_id)
            .map(|channels| {
                channels
                    .iter()
                    .filter(|(_, channel)| channel.connection_id == connection_id)
                    .map(|(id, _)| *id)
                    .collect()
            })
            .unwrap_or_default()
    };
    for channel_id in channels {
        let removed = close_channel_streams(&state.plane, device_id, channel_id).await;
        for id in removed {
            send_control(
                &state,
                device_id,
                &ControlMessage::StreamClose {
                    stream_id: id.to_string(),
                    reason: Some("control_lost".into()),
                },
            )
            .await;
        }
        state
            .plane
            .data_channels
            .write()
            .await
            .get_mut(&device_id)
            .map(|channels| channels.remove(&channel_id));
        if let Some(task) = state
            .plane
            .data_socket_tasks
            .lock()
            .await
            .remove(&(device_id, channel_id))
        {
            task.abort();
        }
    }
    if state
        .plane
        .data_channels
        .read()
        .await
        .get(&device_id)
        .map(|channels| channels.is_empty())
        .unwrap_or(false)
    {
        state.plane.data_channels.write().await.remove(&device_id);
    }
}
#[derive(Clone)]
struct ProbeOutcome {
    ok: bool,
    message: Option<String>,
}

/// Shared token bucket that throttles traffic so the server's bandwidth stays
/// under the configured cap. `rate` is bytes per second; a rate of 0 disables
/// throttling. All tunnels draw from one bucket, so when the cap is reached
/// every connection slows down fairly instead of being dropped.
#[derive(Clone)]
struct BandwidthLimiter {
    mbps: Arc<AtomicU64>,
    state: Arc<tokio::sync::Mutex<BucketState>>,
}

struct BucketState {
    tokens: f64,
    last: Instant,
}

impl BandwidthLimiter {
    fn new(mbps: u64) -> Self {
        Self {
            mbps: Arc::new(AtomicU64::new(mbps)),
            state: Arc::new(tokio::sync::Mutex::new(BucketState {
                tokens: mbps as f64 * 1_000_000.0 / 8.0,
                last: Instant::now(),
            })),
        }
    }

    fn current_mbps(&self) -> u64 {
        self.mbps.load(Ordering::Relaxed)
    }

    fn set_mbps(&self, mbps: u64) {
        self.mbps.store(mbps, Ordering::Relaxed);
    }

    async fn acquire(&self, bytes: usize) {
        let mbps = self.mbps.load(Ordering::Relaxed);
        if mbps == 0 {
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
            tokio::time::sleep(StdDuration::from_secs_f64(wait.min(0.5))).await;
            state = self.state.lock().await;
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[tokio::test]
    async fn bandwidth_limiter_caps_throughput() {
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
    async fn bandwidth_limiter_disabled_passes_through() {
        let limiter = BandwidthLimiter::new(1);
        limiter.set_mbps(0);
        let started = Instant::now();
        for _ in 0..100 {
            limiter.acquire(64 * 1024).await;
        }
        assert!(started.elapsed().as_millis() < 500);
    }

    #[tokio::test]
    async fn stale_control_cleanup_keeps_new_session() {
        let device = Uuid::new_v4();
        let old_connection = Uuid::new_v4();
        let new_connection = Uuid::new_v4();
        let (tx, _rx) = mpsc::channel::<Message>(8);
        let mut sessions = HashMap::new();
        sessions.insert(
            device,
            SessionEntry {
                connection_id: new_connection,
                tx,
            },
        );
        // A stale control loop finishing after a fast reconnect must not
        // remove the newer session registered under the same device.
        assert!(!remove_session_if_owned(
            &mut sessions,
            device,
            old_connection
        ));
        assert!(sessions.contains_key(&device));
        assert!(remove_session_if_owned(
            &mut sessions,
            device,
            new_connection
        ));
        assert!(!sessions.contains_key(&device));
    }

    #[tokio::test]
    async fn routes_tcp_and_udp_concurrently_without_hanging() {
        let plane = DataPlane::default();
        let device = Uuid::new_v4();
        let tcp_id: u128 = 1;
        let udp_id: u128 = 2;
        let (tcp_tx, mut tcp_rx) = mpsc::channel::<Vec<u8>>(4096);
        plane.streams.write().await.insert(
            tcp_id,
            StreamEntry {
                device_id: device,
                data_channel: 1,
                tx: tcp_tx,
            },
        );
        let (udp_tx, mut udp_rx) = mpsc::channel::<Vec<u8>>(4096);
        plane.udp_sessions.write().await.insert(
            udp_id,
            UdpSession {
                device_id: device,
                connection_id: Uuid::new_v4(),
                tunnel_id: Uuid::new_v4(),
                data_channel: 1,
                peer: "127.0.0.1:1000".parse().unwrap(),
                outbox: udp_tx,
                last_seen: Instant::now(),
            },
        );
        // Hammer both kinds of frames from many tasks at once; the routing
        // function must never hang (regression: shared data-plane freeze).
        let result = tokio::time::timeout(StdDuration::from_secs(5), async {
            let mut tasks = Vec::new();
            for _ in 0..20 {
                let plane = plane.clone();
                tasks.push(tokio::spawn(async move {
                    for _ in 0..50 {
                        assert_eq!(
                            route_stream_data(&plane, tcp_id, b"tcp-data").await,
                            RouteOutcome::Ok
                        );
                        assert_eq!(
                            route_stream_data(&plane, udp_id, b"udp-data").await,
                            RouteOutcome::Ok
                        );
                    }
                }));
            }
            for task in tasks {
                task.await.unwrap();
            }
        })
        .await;
        assert!(result.is_ok(), "concurrent TCP+UDP routing hung or failed");
        let mut tcp_received = 0;
        while tcp_rx.try_recv().is_ok() {
            tcp_received += 1;
        }
        let mut udp_received = 0;
        while udp_rx.try_recv().is_ok() {
            udp_received += 1;
        }
        assert_eq!(tcp_received, 1000);
        assert_eq!(udp_received, 1000);
    }

    #[tokio::test]
    async fn closing_one_channel_preserves_the_other() {
        let plane = DataPlane::default();
        let device = Uuid::new_v4();
        for (id, channel) in [(1u128, 1u16), (2, 1), (3, 2), (4, 2)] {
            let (tx, _rx) = mpsc::channel::<Vec<u8>>(8);
            plane.streams.write().await.insert(
                id,
                StreamEntry {
                    device_id: device,
                    data_channel: channel,
                    tx,
                },
            );
        }
        let removed = close_channel_streams(&plane, device, 1).await;
        let mut removed = removed;
        removed.sort_unstable();
        assert_eq!(removed, vec![1, 2]);
        let remaining: Vec<(u128, u16)> = plane
            .streams
            .read()
            .await
            .iter()
            .map(|(id, entry)| (*id, entry.data_channel))
            .collect();
        let mut remaining = remaining;
        remaining.sort_unstable();
        assert_eq!(remaining, vec![(3, 2), (4, 2)]);
    }

    #[tokio::test]
    async fn routes_zero_length_udp_datagram() {
        let plane = DataPlane::default();
        let udp_id: u128 = 9;
        let (outbox, mut rx) = mpsc::channel::<Vec<u8>>(8);
        plane.udp_sessions.write().await.insert(
            udp_id,
            UdpSession {
                device_id: Uuid::new_v4(),
                connection_id: Uuid::new_v4(),
                tunnel_id: Uuid::new_v4(),
                data_channel: 1,
                peer: "127.0.0.1:1000".parse().unwrap(),
                outbox,
                last_seen: Instant::now(),
            },
        );
        assert_eq!(
            route_stream_data(&plane, udp_id, &[]).await,
            RouteOutcome::Ok
        );
        let received = tokio::time::timeout(StdDuration::from_secs(1), rx.recv())
            .await
            .expect("empty datagram was not relayed")
            .expect("channel closed");
        assert!(received.is_empty());
    }
}
#[derive(Serialize, FromRow)]
struct Device {
    id: Uuid,
    name: String,
    status: String,
    latency_ms: i32,
    last_seen_at: Option<chrono::DateTime<Utc>>,
}
#[derive(Clone, Serialize, FromRow)]
struct TunnelRecord {
    id: Uuid,
    name: String,
    kind: String,
    public_port: i32,
    local_host: String,
    local_port: i32,
    enabled: bool,
    max_connections: i32,
    device_id: Uuid,
    status: String,
    connections: i64,
}
#[derive(Deserialize)]
struct Login {
    email: String,
    password: String,
}
#[derive(Serialize, Deserialize)]
struct Settings {
    bandwidth_limit_mbps: u64,
}
#[derive(Deserialize)]
struct CreateTunnel {
    name: String,
    kind: TunnelKind,
    public_port: u16,
    local_host: String,
    local_port: u16,
    device_id: Uuid,
    max_connections: Option<u16>,
}
#[derive(Deserialize)]
struct UpdateTunnel {
    name: String,
    kind: TunnelKind,
    public_port: u16,
    local_host: String,
    local_port: u16,
    device_id: Uuid,
    max_connections: Option<u16>,
    enabled: Option<bool>,
}
#[derive(Deserialize)]
struct CreateKey {
    label: String,
    device_id: Option<Uuid>,
    expires_in_days: Option<i64>,
}
#[derive(Deserialize)]
struct UpdateKey {
    label: Option<String>,
    /// None keeps the current binding, Some(None) unbinds, Some(Some(id)) rebinds.
    device_id: Option<Option<Uuid>>,
    /// None keeps the current expiry, Some(0) clears it, Some(days) sets a new one.
    expires_in_days: Option<i64>,
}
#[derive(Serialize, FromRow)]
struct AccessKey {
    id: Uuid,
    label: String,
    device_id: Option<Uuid>,
    device_name: Option<String>,
    created_at: chrono::DateTime<Utc>,
    expires_at: Option<chrono::DateTime<Utc>>,
    revoked_at: Option<chrono::DateTime<Utc>>,
    last_used_at: Option<chrono::DateTime<Utc>>,
    status: String,
}
#[derive(Serialize, FromRow)]
struct LogEntry {
    id: Uuid,
    actor_id: Option<Uuid>,
    actor_email: Option<String>,
    action: String,
    subject: String,
    created_at: chrono::DateTime<Utc>,
}
#[derive(Serialize, Deserialize)]
struct Claims {
    sub: String,
    role: String,
    exp: usize,
}
#[derive(Clone)]
struct Admin {
    id: Uuid,
}

#[tokio::main]
async fn main() -> anyhow::Result<()> {
    tracing_subscriber::fmt()
        .with_env_filter("tunnel_server=info,tower_http=info")
        .init();
    let database_url = env::var("DATABASE_URL").expect("DATABASE_URL is required");
    let redis_url = env::var("REDIS_URL").expect("REDIS_URL is required");
    let db = PgPoolOptions::new()
        .max_connections(10)
        .connect(&database_url)
        .await?;
    sqlx::migrate!("../../deploy/migrations").run(&db).await?;
    bootstrap_admin(&db).await?;
    let tunnel_port_start = read_port("TUNNEL_PORT_START", 10000)?;
    let tunnel_port_end = read_port("TUNNEL_PORT_END", 10100)?;
    if tunnel_port_start > tunnel_port_end {
        anyhow::bail!("TUNNEL_PORT_START must not be greater than TUNNEL_PORT_END");
    }
    let bandwidth = BandwidthLimiter::new(
        env::var("BANDWIDTH_LIMIT_MBPS")
            .ok()
            .and_then(|value| value.parse().ok())
            .unwrap_or(0),
    );
    let udp_session_idle_secs = env::var("UDP_SESSION_IDLE_SECS")
        .ok()
        .and_then(|value| value.parse().ok())
        .filter(|secs| *secs >= 30)
        .unwrap_or(120);
    let data_channels_max = env::var("DATA_CHANNELS_MAX")
        .ok()
        .and_then(|value| value.parse().ok())
        .filter(|channels| (1..=16).contains(channels))
        .unwrap_or(4);
    let shutdown_drain_secs = env::var("SHUTDOWN_DRAIN_SECS")
        .ok()
        .and_then(|value| value.parse().ok())
        .filter(|secs| *secs <= 300)
        .unwrap_or(10);
    if let Some(stored) = sqlx::query_scalar::<_, String>(
        "SELECT value FROM settings WHERE key = 'bandwidth_limit_mbps'",
    )
    .fetch_optional(&db)
    .await?
    .and_then(|value| value.parse().ok())
    {
        bandwidth.set_mbps(stored);
    }
    let state = AppState {
        db,
        redis: redis::Client::open(redis_url)?,
        jwt_secret: Arc::new(env::var("JWT_SECRET").expect("JWT_SECRET is required")),
        admin_token_ttl_hours: env::var("ADMIN_TOKEN_TTL_HOURS")
            .ok()
            .and_then(|value| value.parse().ok())
            .filter(|hours| *hours > 0)
            .unwrap_or(24 * 30),
        bootstrap_agent_token_hash: env::var("BOOTSTRAP_AGENT_TOKEN")
            .ok()
            .filter(|token| !token.trim().is_empty())
            .map(|token| format!("{:x}", sha2::Sha256::digest(token.as_bytes()))),
        listeners: Arc::new(RwLock::new(HashMap::new())),
        udp_session_idle_secs,
        probes: Arc::new(RwLock::new(HashMap::new())),
        bandwidth,
        tunnel_port_start,
        tunnel_port_end,
        data_channels_max,
        shutdown_drain_secs,
        accepting: Arc::new(std::sync::atomic::AtomicBool::new(true)),
        plane: DataPlane::default(),
    };
    for id in sqlx::query_scalar::<_, Uuid>("SELECT id FROM tunnels WHERE enabled")
        .fetch_all(&state.db)
        .await?
    {
        start_listener(state.clone(), id)
            .await
            .map_err(anyhow::Error::msg)?;
    }
    let app = Router::new()
        .route("/healthz", get(|| async { "ok" }))
        .route("/api/v1/auth/login", post(login))
        .route("/api/v1/summary", get(summary))
        .route("/api/v1/settings", get(get_settings).put(update_settings))
        .route("/api/v1/logs", get(list_logs))
        .route("/api/v1/devices", get(list_devices))
        .route("/api/v1/tunnels", get(list_tunnels).post(create_tunnel))
        .route(
            "/api/v1/tunnels/{id}",
            put(update_tunnel).delete(delete_tunnel),
        )
        .route("/api/v1/tunnels/{id}/toggle", post(toggle_tunnel))
        .route("/api/v1/tunnels/{id}/probe", post(probe_tunnel))
        .route("/api/v1/keys", get(list_keys).post(create_key))
        .route("/api/v1/keys/{id}", put(update_key).delete(delete_key))
        .route("/api/v1/keys/{id}/revoke", post(revoke_key))
        .route("/control", get(control_socket))
        .route("/data", get(data_socket))
        .layer(CorsLayer::permissive())
        .layer(TraceLayer::new_for_http())
        .with_state(state.clone());
    let port = env::var("MANAGEMENT_PORT")
        .unwrap_or_else(|_| "18080".into())
        .parse()?;
    let listener = TcpListener::bind(("0.0.0.0", port)).await?;
    tracing::info!(port, "management and control listener ready");
    axum::serve(listener, app)
        .with_graceful_shutdown(shutdown_signal(state))
        .await?;
    Ok(())
}

/// Stops accepting new public connections on shutdown, tells every agent why
/// its streams are closing, waits for short requests to drain, then lets the
/// process exit (dropping the tunnel listener tasks with the runtime).
async fn shutdown_signal(state: AppState) {
    let ctrl_c = tokio::signal::ctrl_c();
    #[cfg(unix)]
    let terminate = async {
        if let Ok(mut signal) =
            tokio::signal::unix::signal(tokio::signal::unix::SignalKind::terminate())
        {
            signal.recv().await;
        }
    };
    #[cfg(not(unix))]
    let terminate = std::future::pending::<()>();
    tokio::select! {
        _ = ctrl_c => {},
        _ = terminate => {},
    }
    tracing::info!(
        "shutdown signal received; draining for {}s",
        state.shutdown_drain_secs
    );
    state.accepting.store(false, Ordering::Relaxed);
    let tcp: Vec<(u128, Uuid)> = state
        .plane
        .streams
        .read()
        .await
        .iter()
        .map(|(id, entry)| (*id, entry.device_id))
        .collect();
    for (id, device_id) in tcp {
        state.plane.streams.write().await.remove(&id);
        send_control(
            &state,
            device_id,
            &ControlMessage::StreamClose {
                stream_id: id.to_string(),
                reason: Some("server_shutdown".into()),
            },
        )
        .await;
    }
    let udp: Vec<u128> = state
        .plane
        .udp_sessions
        .read()
        .await
        .keys()
        .copied()
        .collect();
    for id in udp {
        if let Some(session) = state.plane.udp_sessions.read().await.get(&id).cloned() {
            state.plane.udp_sessions.write().await.remove(&id);
            send_control(
                &state,
                session.device_id,
                &ControlMessage::StreamClose {
                    stream_id: id.to_string(),
                    reason: Some("server_shutdown".into()),
                },
            )
            .await;
        }
    }
    tokio::time::sleep(StdDuration::from_secs(state.shutdown_drain_secs)).await;
}

fn read_port(name: &str, default: u16) -> anyhow::Result<u16> {
    Ok(env::var(name)
        .unwrap_or_else(|_| default.to_string())
        .parse::<u16>()?)
}

async fn bootstrap_admin(db: &PgPool) -> anyhow::Result<()> {
    let (Ok(email), Ok(password)) = (
        env::var("BOOTSTRAP_ADMIN_EMAIL"),
        env::var("BOOTSTRAP_ADMIN_PASSWORD"),
    ) else {
        return Ok(());
    };
    if email.trim().is_empty() || password.is_empty() {
        return Ok(());
    }
    if sqlx::query_scalar::<_, i64>("SELECT count(*) FROM users WHERE role = 'admin'")
        .fetch_one(db)
        .await?
        > 0
    {
        return Ok(());
    }
    let hash = argon2::Argon2::default()
        .hash_password(
            password.as_bytes(),
            &argon2::password_hash::SaltString::generate(&mut rand_core::OsRng),
        )
        .map_err(|error| anyhow::Error::msg(error.to_string()))?
        .to_string();
    let workspace = Uuid::new_v4();
    sqlx::query("INSERT INTO workspaces(id,name) VALUES($1,'Default workspace')")
        .bind(workspace)
        .execute(db)
        .await?;
    sqlx::query(
        "INSERT INTO users(id,workspace_id,email,password_hash,role) VALUES($1,$2,$3,$4,'admin')",
    )
    .bind(Uuid::new_v4())
    .bind(workspace)
    .bind(email)
    .bind(hash)
    .execute(db)
    .await?;
    tracing::info!("bootstrap administrator created");
    Ok(())
}

async fn admin(headers: &HeaderMap, state: &AppState) -> Result<Admin, StatusCode> {
    let value = headers
        .get(header::AUTHORIZATION)
        .and_then(|v| v.to_str().ok())
        .and_then(|v| v.strip_prefix("Bearer "))
        .ok_or(StatusCode::UNAUTHORIZED)?;
    let claims = jwt_decode::<Claims>(
        value,
        &DecodingKey::from_secret(state.jwt_secret.as_bytes()),
        &Validation::default(),
    )
    .map_err(|_| StatusCode::UNAUTHORIZED)?
    .claims;
    if claims.role != "admin" {
        return Err(StatusCode::FORBIDDEN);
    }
    Ok(Admin {
        id: Uuid::parse_str(&claims.sub).map_err(|_| StatusCode::UNAUTHORIZED)?,
    })
}
async fn login(
    State(state): State<AppState>,
    Json(input): Json<Login>,
) -> Result<Json<serde_json::Value>, StatusCode> {
    let user: (Uuid, String, String) =
        match sqlx::query_as("SELECT id, password_hash, role FROM users WHERE email = $1")
            .bind(&input.email)
            .fetch_optional(&state.db)
            .await
            .map_err(|_| StatusCode::INTERNAL_SERVER_ERROR)?
        {
            Some(user) => user,
            None => {
                audit(&state.db, None, "auth.login_failed", &input.email).await;
                return Err(StatusCode::UNAUTHORIZED);
            }
        };
    let valid = argon2::PasswordHash::new(&user.1)
        .ok()
        .and_then(|h| {
            argon2::PasswordVerifier::verify_password(
                &argon2::Argon2::default(),
                input.password.as_bytes(),
                &h,
            )
            .ok()
        })
        .is_some();
    if !valid {
        audit(&state.db, None, "auth.login_failed", &input.email).await;
        return Err(StatusCode::UNAUTHORIZED);
    }
    audit(&state.db, Some(user.0), "auth.login", &input.email).await;
    let claims = Claims {
        sub: user.0.to_string(),
        role: user.2,
        exp: (Utc::now() + Duration::hours(state.admin_token_ttl_hours)).timestamp() as usize,
    };
    let token = jwt_encode(
        &Header::default(),
        &claims,
        &EncodingKey::from_secret(state.jwt_secret.as_bytes()),
    )
    .map_err(|_| StatusCode::INTERNAL_SERVER_ERROR)?;
    Ok(Json(serde_json::json!({"access_token": token})))
}
async fn summary(
    State(state): State<AppState>,
    headers: HeaderMap,
) -> Result<Json<serde_json::Value>, StatusCode> {
    admin(&headers, &state).await?;
    let row: (i64, i64, i64) = sqlx::query_as("SELECT (SELECT count(*) FROM devices), (SELECT count(*) FROM devices WHERE status = 'online'), (SELECT count(*) FROM tunnels)").fetch_one(&state.db).await.map_err(|_| StatusCode::INTERNAL_SERVER_ERROR)?;
    Ok(Json(
        serde_json::json!({"devices":row.0,"online_devices":row.1,"tunnels":row.2,"active_connections":0}),
    ))
}
async fn get_settings(
    State(state): State<AppState>,
    headers: HeaderMap,
) -> Result<Json<Settings>, StatusCode> {
    admin(&headers, &state).await?;
    let stored: Option<u64> = sqlx::query_scalar::<_, String>(
        "SELECT value FROM settings WHERE key = 'bandwidth_limit_mbps'",
    )
    .fetch_optional(&state.db)
    .await
    .map_err(|_| StatusCode::INTERNAL_SERVER_ERROR)?
    .and_then(|value| value.parse().ok());
    Ok(Json(Settings {
        bandwidth_limit_mbps: stored.unwrap_or_else(|| state.bandwidth.current_mbps()),
    }))
}
async fn update_settings(
    State(state): State<AppState>,
    headers: HeaderMap,
    Json(input): Json<Settings>,
) -> Result<Json<Settings>, (StatusCode, String)> {
    let actor = admin(&headers, &state)
        .await
        .map_err(|s| (s, "Unauthorized".into()))?;
    if input.bandwidth_limit_mbps > 10_000 {
        return Err((
            StatusCode::UNPROCESSABLE_ENTITY,
            "bandwidth_limit_mbps must be at most 10000".into(),
        ));
    }
    sqlx::query(
        "INSERT INTO settings(key, value) VALUES('bandwidth_limit_mbps', $1) \
         ON CONFLICT(key) DO UPDATE SET value = EXCLUDED.value",
    )
    .bind(input.bandwidth_limit_mbps.to_string())
    .execute(&state.db)
    .await
    .map_err(|_| {
        (
            StatusCode::INTERNAL_SERVER_ERROR,
            "Could not save settings".into(),
        )
    })?;
    state.bandwidth.set_mbps(input.bandwidth_limit_mbps);
    // Reconfigure every online agent so its source-side throttle tracks the
    // server cap. This keeps the agent -> server direction from saturating
    // the shared control WebSocket whenever the admin changes the limit.
    let bandwidth_config = ControlMessage::BandwidthConfig {
        mbps: input.bandwidth_limit_mbps,
    };
    if let Ok(payload) = encode(&bandwidth_config) {
        let message = Message::Text(String::from_utf8_lossy(&payload).into_owned().into());
        for entry in state.plane.sessions.read().await.values() {
            let _ = entry.tx.try_send(message.clone());
        }
    }
    audit(
        &state.db,
        Some(actor.id),
        "settings.bandwidth_updated",
        &input.bandwidth_limit_mbps.to_string(),
    )
    .await;
    Ok(Json(input))
}
async fn list_devices(
    State(state): State<AppState>,
    headers: HeaderMap,
) -> Result<Json<Vec<Device>>, StatusCode> {
    admin(&headers, &state).await?;
    let rows = sqlx::query_as::<_, Device>(
        "SELECT id,name,status,latency_ms,last_seen_at FROM devices ORDER BY name",
    )
    .fetch_all(&state.db)
    .await
    .map_err(|_| StatusCode::INTERNAL_SERVER_ERROR)?;
    Ok(Json(rows))
}
async fn list_tunnels(
    State(state): State<AppState>,
    headers: HeaderMap,
) -> Result<Json<Vec<TunnelRecord>>, StatusCode> {
    admin(&headers, &state).await?;
    let rows = sqlx::query_as::<_, TunnelRecord>("SELECT t.id,t.name,t.kind,t.public_port,t.local_host,t.local_port,t.enabled,t.max_connections,t.device_id,CASE WHEN d.status='online' THEN 'ready' ELSE 'offline' END status,0::bigint connections FROM tunnels t JOIN devices d ON d.id=t.device_id ORDER BY t.public_port").fetch_all(&state.db).await.map_err(|_| StatusCode::INTERNAL_SERVER_ERROR)?;
    Ok(Json(rows))
}
async fn create_tunnel(
    State(state): State<AppState>,
    headers: HeaderMap,
    Json(input): Json<CreateTunnel>,
) -> Result<(StatusCode, Json<TunnelRecord>), (StatusCode, String)> {
    let actor = admin(&headers, &state)
        .await
        .map_err(|s| (s, "Unauthorized".into()))?;
    if input.public_port < state.tunnel_port_start || input.public_port > state.tunnel_port_end {
        return Err((
            StatusCode::UNPROCESSABLE_ENTITY,
            format!(
                "Public port must be between {} and {}",
                state.tunnel_port_start, state.tunnel_port_end
            ),
        ));
    }
    let kind = match input.kind {
        TunnelKind::Tcp => "tcp",
        TunnelKind::Http => "http",
        TunnelKind::Udp => "udp",
    };
    let id = Uuid::new_v4();
    let result = sqlx::query("INSERT INTO tunnels(id,name,kind,public_port,local_host,local_port,enabled,max_connections,device_id) VALUES($1,$2,$3,$4,$5,$6,true,$7,$8)").bind(id).bind(&input.name).bind(kind).bind(input.public_port as i32).bind(&input.local_host).bind(input.local_port as i32).bind(input.max_connections.unwrap_or(100) as i32).bind(input.device_id).execute(&state.db).await;
    if result.is_err() {
        return Err((
            StatusCode::CONFLICT,
            "Public port is unavailable or device does not exist".into(),
        ));
    }
    audit(&state.db, Some(actor.id), "tunnel.created", &input.name).await;
    let tunnel = get_tunnel(&state.db, id).await.map_err(|_| {
        (
            StatusCode::INTERNAL_SERVER_ERROR,
            "Could not create tunnel".into(),
        )
    })?;
    start_listener(state.clone(), tunnel.id)
        .await
        .map_err(|e| (StatusCode::INTERNAL_SERVER_ERROR, e))?;
    sync_device_tunnels(&state, tunnel.device_id).await;
    Ok((StatusCode::CREATED, Json(tunnel)))
}
async fn toggle_tunnel(
    State(state): State<AppState>,
    headers: HeaderMap,
    Path(id): Path<Uuid>,
) -> Result<Json<TunnelRecord>, StatusCode> {
    let actor = admin(&headers, &state).await?;
    sqlx::query("UPDATE tunnels SET enabled=NOT enabled WHERE id=$1")
        .bind(id)
        .execute(&state.db)
        .await
        .map_err(|_| StatusCode::INTERNAL_SERVER_ERROR)?;
    let tunnel = get_tunnel(&state.db, id)
        .await
        .map_err(|_| StatusCode::NOT_FOUND)?;
    audit(&state.db, Some(actor.id), "tunnel.toggled", &tunnel.name).await;
    if tunnel.enabled {
        start_listener(state.clone(), id)
            .await
            .map_err(|_| StatusCode::INTERNAL_SERVER_ERROR)?;
    } else {
        remove_listener(&state, id).await;
    }
    sync_device_tunnels(&state, tunnel.device_id).await;
    Ok(Json(tunnel))
}
async fn update_tunnel(
    State(state): State<AppState>,
    headers: HeaderMap,
    Path(id): Path<Uuid>,
    Json(input): Json<UpdateTunnel>,
) -> Result<Json<TunnelRecord>, (StatusCode, String)> {
    let actor = admin(&headers, &state)
        .await
        .map_err(|s| (s, "Unauthorized".into()))?;
    if input.public_port < state.tunnel_port_start || input.public_port > state.tunnel_port_end {
        return Err((
            StatusCode::UNPROCESSABLE_ENTITY,
            format!(
                "Public port must be between {} and {}",
                state.tunnel_port_start, state.tunnel_port_end
            ),
        ));
    }
    let current = get_tunnel(&state.db, id)
        .await
        .map_err(|_| (StatusCode::NOT_FOUND, "Tunnel not found".into()))?;
    let kind = match input.kind {
        TunnelKind::Tcp => "tcp",
        TunnelKind::Http => "http",
        TunnelKind::Udp => "udp",
    };
    let enabled = input.enabled.unwrap_or(current.enabled);
    let result = sqlx::query(
        "UPDATE tunnels SET name=$1,kind=$2,public_port=$3,local_host=$4,local_port=$5,enabled=$6,max_connections=$7,device_id=$8 WHERE id=$9",
    )
    .bind(&input.name)
    .bind(kind)
    .bind(input.public_port as i32)
    .bind(&input.local_host)
    .bind(input.local_port as i32)
    .bind(enabled)
    .bind(input.max_connections.unwrap_or(current.max_connections as u16) as i32)
    .bind(input.device_id)
    .bind(id)
    .execute(&state.db)
    .await;
    if result.is_err() {
        return Err((
            StatusCode::CONFLICT,
            "Public port is unavailable or device does not exist".into(),
        ));
    }
    audit(&state.db, Some(actor.id), "tunnel.updated", &input.name).await;
    // The listener captures the tunnel config, so restart it whenever the tunnel is updated.
    remove_listener(&state, id).await;
    if enabled {
        start_listener(state.clone(), id)
            .await
            .map_err(|error| (StatusCode::INTERNAL_SERVER_ERROR, error))?;
    }
    sync_device_tunnels(&state, current.device_id).await;
    sync_device_tunnels(&state, input.device_id).await;
    let tunnel = get_tunnel(&state.db, id).await.map_err(|_| {
        (
            StatusCode::INTERNAL_SERVER_ERROR,
            "Could not reload tunnel".into(),
        )
    })?;
    Ok(Json(tunnel))
}
async fn delete_tunnel(
    State(state): State<AppState>,
    headers: HeaderMap,
    Path(id): Path<Uuid>,
) -> Result<Json<serde_json::Value>, (StatusCode, String)> {
    let actor = admin(&headers, &state)
        .await
        .map_err(|s| (s, "Unauthorized".into()))?;
    let current = get_tunnel(&state.db, id)
        .await
        .map_err(|_| (StatusCode::NOT_FOUND, "Tunnel not found".into()))?;
    sqlx::query("DELETE FROM tunnels WHERE id=$1")
        .bind(id)
        .execute(&state.db)
        .await
        .map_err(|_| {
            (
                StatusCode::INTERNAL_SERVER_ERROR,
                "Could not delete tunnel".into(),
            )
        })?;
    remove_listener(&state, id).await;
    sync_device_tunnels(&state, current.device_id).await;
    audit(&state.db, Some(actor.id), "tunnel.deleted", &current.name).await;
    Ok(Json(serde_json::json!({"deleted": true})))
}

async fn probe_tunnel(
    State(state): State<AppState>,
    headers: HeaderMap,
    Path(id): Path<Uuid>,
) -> Result<Json<serde_json::Value>, (StatusCode, String)> {
    let _actor = admin(&headers, &state)
        .await
        .map_err(|s| (s, "Unauthorized".into()))?;
    let tunnel = get_tunnel(&state.db, id)
        .await
        .map_err(|_| (StatusCode::NOT_FOUND, "Tunnel not found".into()))?;
    let listener_active = state.listeners.read().await.contains_key(&id);
    let agent_online = state
        .plane
        .sessions
        .read()
        .await
        .contains_key(&tunnel.device_id);
    if !listener_active || !agent_online {
        let message = if !listener_active {
            "tunnel listener is not active"
        } else {
            "agent is offline"
        };
        return Ok(Json(serde_json::json!({
            "ok": false,
            "listener": listener_active,
            "agent_online": agent_online,
            "local": serde_json::Value::Null,
            "message": message,
        })));
    }
    let probe_id = Uuid::new_v4().to_string();
    let (tx, rx) = oneshot::channel::<ProbeOutcome>();
    state.probes.write().await.insert(probe_id.clone(), tx);
    let probe = ControlMessage::ProbeLocal {
        probe_id: probe_id.clone(),
        tunnel_id: tunnel.id.to_string(),
    };
    if !send_control(&state, tunnel.device_id, &probe).await {
        state.probes.write().await.remove(&probe_id);
        return Ok(Json(serde_json::json!({
            "ok": false,
            "listener": listener_active,
            "agent_online": false,
            "local": serde_json::Value::Null,
            "message": "agent went offline while probing",
        })));
    }
    match tokio::time::timeout(StdDuration::from_secs(10), rx).await {
        Ok(Ok(outcome)) => Ok(Json(serde_json::json!({
            "ok": outcome.ok,
            "listener": listener_active,
            "agent_online": agent_online,
            "local": outcome.ok,
            "message": outcome.message,
        }))),
        Ok(Err(_)) => Err((
            StatusCode::INTERNAL_SERVER_ERROR,
            "Probe channel failed".into(),
        )),
        Err(_) => {
            state.probes.write().await.remove(&probe_id);
            Ok(Json(serde_json::json!({
                "ok": false,
                "listener": listener_active,
                "agent_online": agent_online,
                "local": serde_json::Value::Null,
                "message": "probe timed out; agent may be running an older version",
            })))
        }
    }
}

async fn list_keys(
    State(state): State<AppState>,
    headers: HeaderMap,
) -> Result<Json<Vec<AccessKey>>, StatusCode> {
    admin(&headers, &state).await?;
    let rows = sqlx::query_as::<_, AccessKey>(
        "SELECT t.id,t.label,t.device_id,d.name AS device_name,t.created_at,t.expires_at,t.revoked_at,t.last_used_at,\
         CASE WHEN t.revoked_at IS NOT NULL THEN 'revoked' WHEN t.expires_at IS NOT NULL AND t.expires_at<=now() THEN 'expired' ELSE 'active' END AS status \
         FROM access_tokens t LEFT JOIN devices d ON d.id=t.device_id ORDER BY t.created_at DESC",
    )
    .fetch_all(&state.db)
    .await
    .map_err(|_| StatusCode::INTERNAL_SERVER_ERROR)?;
    Ok(Json(rows))
}
async fn create_key(
    State(state): State<AppState>,
    headers: HeaderMap,
    Json(input): Json<CreateKey>,
) -> Result<(StatusCode, Json<serde_json::Value>), (StatusCode, String)> {
    let actor = admin(&headers, &state)
        .await
        .map_err(|s| (s, "Unauthorized".into()))?;
    let label = input.label.trim().to_string();
    if label.is_empty() || label.chars().count() > 100 {
        return Err((
            StatusCode::UNPROCESSABLE_ENTITY,
            "Label must be between 1 and 100 characters".into(),
        ));
    }
    if input.expires_in_days.is_some_and(|days| days < 1) {
        return Err((
            StatusCode::UNPROCESSABLE_ENTITY,
            "expires_in_days must be at least 1".into(),
        ));
    }
    if let Some(device_id) = input.device_id {
        let exists = sqlx::query_scalar::<_, Uuid>("SELECT id FROM devices WHERE id=$1")
            .bind(device_id)
            .fetch_optional(&state.db)
            .await
            .map_err(|_| (StatusCode::INTERNAL_SERVER_ERROR, "Query failed".into()))?;
        if exists.is_none() {
            return Err((
                StatusCode::UNPROCESSABLE_ENTITY,
                "Device does not exist".into(),
            ));
        }
    }
    let mut bytes = [0_u8; 32];
    rand_core::OsRng.fill_bytes(&mut bytes);
    let token = bytes
        .iter()
        .map(|byte| format!("{byte:02x}"))
        .collect::<String>();
    let token_hash = format!("{:x}", sha2::Sha256::digest(token.as_bytes()));
    let id = Uuid::new_v4();
    let expires_at = input
        .expires_in_days
        .map(|days| Utc::now() + Duration::days(days));
    let result = sqlx::query(
        "INSERT INTO access_tokens(id,device_id,label,token_hash,expires_at) VALUES($1,$2,$3,$4,$5)",
    )
    .bind(id)
    .bind(input.device_id)
    .bind(&label)
    .bind(&token_hash)
    .bind(expires_at)
    .execute(&state.db)
    .await;
    if result.is_err() {
        return Err((
            StatusCode::INTERNAL_SERVER_ERROR,
            "Could not create access key".into(),
        ));
    }
    audit(&state.db, Some(actor.id), "create_access_key", &label).await;
    Ok((
        StatusCode::CREATED,
        Json(serde_json::json!({"id": id, "token": token})),
    ))
}
async fn update_key(
    State(state): State<AppState>,
    headers: HeaderMap,
    Path(id): Path<Uuid>,
    Json(input): Json<UpdateKey>,
) -> Result<Json<AccessKey>, (StatusCode, String)> {
    let actor = admin(&headers, &state)
        .await
        .map_err(|s| (s, "Unauthorized".into()))?;
    let current = get_access_key(&state.db, id)
        .await
        .map_err(|_| (StatusCode::NOT_FOUND, "Access key not found".into()))?;
    let label = input
        .label
        .map(|value| value.trim().to_string())
        .unwrap_or(current.label);
    if label.is_empty() || label.chars().count() > 100 {
        return Err((
            StatusCode::UNPROCESSABLE_ENTITY,
            "Label must be between 1 and 100 characters".into(),
        ));
    }
    let device_id = match input.device_id {
        Some(device_id) => device_id,
        None => current.device_id,
    };
    if let Some(target) = device_id {
        let exists = sqlx::query_scalar::<_, Uuid>("SELECT id FROM devices WHERE id=$1")
            .bind(target)
            .fetch_optional(&state.db)
            .await
            .map_err(|_| (StatusCode::INTERNAL_SERVER_ERROR, "Query failed".into()))?;
        if exists.is_none() {
            return Err((
                StatusCode::UNPROCESSABLE_ENTITY,
                "Device does not exist".into(),
            ));
        }
    }
    let expires_at = match input.expires_in_days {
        Some(0) => None,
        Some(days) if days >= 1 => Some(Utc::now() + Duration::days(days)),
        Some(_) => {
            return Err((
                StatusCode::UNPROCESSABLE_ENTITY,
                "expires_in_days must be 0 or at least 1".into(),
            ));
        }
        None => current.expires_at,
    };
    sqlx::query("UPDATE access_tokens SET label=$1,device_id=$2,expires_at=$3 WHERE id=$4")
        .bind(&label)
        .bind(device_id)
        .bind(expires_at)
        .bind(id)
        .execute(&state.db)
        .await
        .map_err(|_| {
            (
                StatusCode::INTERNAL_SERVER_ERROR,
                "Could not update access key".into(),
            )
        })?;
    audit(&state.db, Some(actor.id), "update_access_key", &label).await;
    let row = get_access_key(&state.db, id).await.map_err(|_| {
        (
            StatusCode::INTERNAL_SERVER_ERROR,
            "Could not reload access key".into(),
        )
    })?;
    Ok(Json(row))
}
async fn delete_key(
    State(state): State<AppState>,
    headers: HeaderMap,
    Path(id): Path<Uuid>,
) -> Result<Json<serde_json::Value>, (StatusCode, String)> {
    let actor = admin(&headers, &state)
        .await
        .map_err(|s| (s, "Unauthorized".into()))?;
    let result = sqlx::query("DELETE FROM access_tokens WHERE id=$1")
        .bind(id)
        .execute(&state.db)
        .await
        .map_err(|_| {
            (
                StatusCode::INTERNAL_SERVER_ERROR,
                "Could not delete access key".into(),
            )
        })?;
    if result.rows_affected() == 0 {
        return Err((StatusCode::NOT_FOUND, "Access key not found".into()));
    }
    audit(
        &state.db,
        Some(actor.id),
        "delete_access_key",
        &id.to_string(),
    )
    .await;
    Ok(Json(serde_json::json!({"deleted": true})))
}
async fn revoke_key(
    State(state): State<AppState>,
    headers: HeaderMap,
    Path(id): Path<Uuid>,
) -> Result<Json<serde_json::Value>, (StatusCode, String)> {
    let actor = admin(&headers, &state)
        .await
        .map_err(|s| (s, "Unauthorized".into()))?;
    let result =
        sqlx::query("UPDATE access_tokens SET revoked_at=now() WHERE id=$1 AND revoked_at IS NULL")
            .bind(id)
            .execute(&state.db)
            .await
            .map_err(|_| {
                (
                    StatusCode::INTERNAL_SERVER_ERROR,
                    "Could not revoke access key".into(),
                )
            })?;
    if result.rows_affected() == 0 {
        return Err((
            StatusCode::NOT_FOUND,
            "Access key not found or already revoked".into(),
        ));
    }
    audit(
        &state.db,
        Some(actor.id),
        "revoke_access_key",
        &id.to_string(),
    )
    .await;
    Ok(Json(serde_json::json!({"revoked": true})))
}

async fn sync_device_tunnels(state: &AppState, device_id: Uuid) {
    let message = ControlMessage::SyncTunnels {
        tunnels: load_specs(&state.db, device_id).await,
    };
    send_control(&state, device_id, &message).await;
}
async fn get_tunnel(db: &PgPool, id: Uuid) -> Result<TunnelRecord, sqlx::Error> {
    sqlx::query_as::<_,TunnelRecord>("SELECT t.id,t.name,t.kind,t.public_port,t.local_host,t.local_port,t.enabled,t.max_connections,t.device_id,CASE WHEN d.status='online' THEN 'ready' ELSE 'offline' END status,0::bigint connections FROM tunnels t JOIN devices d ON d.id=t.device_id WHERE t.id=$1").bind(id).fetch_one(db).await
}
async fn get_access_key(db: &PgPool, id: Uuid) -> Result<AccessKey, sqlx::Error> {
    sqlx::query_as::<_,AccessKey>("SELECT t.id,t.label,t.device_id,d.name AS device_name,t.created_at,t.expires_at,t.revoked_at,t.last_used_at,CASE WHEN t.revoked_at IS NOT NULL THEN 'revoked' WHEN t.expires_at IS NOT NULL AND t.expires_at<=now() THEN 'expired' ELSE 'active' END AS status FROM access_tokens t LEFT JOIN devices d ON d.id=t.device_id WHERE t.id=$1").bind(id).fetch_one(db).await
}
/// Records one admin-side event. `actor` is the signed-in user; `None` is used
/// for attempts where the actor could not be identified (e.g. failed logins).
async fn audit(db: &PgPool, actor: Option<Uuid>, action: &str, subject: &str) {
    let _ = sqlx::query("INSERT INTO audit_events(id,actor_id,action,subject) VALUES($1,$2,$3,$4)")
        .bind(Uuid::new_v4())
        .bind(actor)
        .bind(action)
        .bind(subject)
        .execute(db)
        .await;
}
async fn list_logs(
    State(state): State<AppState>,
    headers: HeaderMap,
    Query(params): Query<HashMap<String, String>>,
) -> Result<Json<Vec<LogEntry>>, StatusCode> {
    admin(&headers, &state).await?;
    let limit = params
        .get("limit")
        .and_then(|value| value.parse::<i64>().ok())
        .unwrap_or(200)
        .clamp(1, 500);
    let rows = sqlx::query_as::<_, LogEntry>(
        "SELECT a.id,a.actor_id,u.email AS actor_email,a.action,a.subject,a.created_at \
         FROM audit_events a LEFT JOIN users u ON u.id=a.actor_id \
         ORDER BY a.created_at DESC, a.id DESC LIMIT $1",
    )
    .bind(limit)
    .fetch_all(&state.db)
    .await
    .map_err(|_| StatusCode::INTERNAL_SERVER_ERROR)?;
    Ok(Json(rows))
}

async fn control_socket(ws: WebSocketUpgrade, State(state): State<AppState>) -> impl IntoResponse {
    ws.on_upgrade(move |socket| control_loop(socket, state))
}
async fn control_loop(socket: WebSocket, state: AppState) {
    let (mut sink, mut source) = socket.split();
    let Some(Ok(Message::Text(first))) = source.next().await else {
        return;
    };
    let Ok(ControlMessage::Register {
        token, device_name, ..
    }) = decode(first.as_bytes())
    else {
        return;
    };
    let token_hash = format!("{:x}", sha2::Sha256::digest(token.as_bytes()));
    let token_row: Option<(Uuid, Option<Uuid>)> = sqlx::query_as(
        "SELECT id, device_id FROM access_tokens WHERE token_hash=$1 AND revoked_at IS NULL AND (expires_at IS NULL OR expires_at>now())",
    )
    .bind(&token_hash)
    .fetch_optional(&state.db)
    .await
    .ok()
    .flatten();
    let device_id = match token_row {
        Some((_, Some(device_id))) => device_id,
        Some((token_id, None)) => {
            match bind_pending_device(&state.db, token_id, &device_name).await {
                Ok(device_id) => device_id,
                Err(error) => {
                    tracing::warn!(%error, "pending access key device registration failed");
                    return;
                }
            }
        }
        None if state.bootstrap_agent_token_hash.as_deref() == Some(token_hash.as_str()) => {
            match bootstrap_device(&state.db, &device_name, &token_hash).await {
                Ok(id) => id,
                Err(error) => {
                    tracing::warn!(%error, "bootstrap device registration failed");
                    return;
                }
            }
        }
        None => {
            let _ = sink
                .send(Message::Text(
                    String::from_utf8(
                        encode(&ControlMessage::Error {
                            code: "invalid_token".into(),
                            message: "Token rejected".into(),
                        })
                        .unwrap(),
                    )
                    .unwrap()
                    .into(),
                ))
                .await;
            return;
        }
    };
    let _ = sqlx::query("UPDATE access_tokens SET last_used_at=now() WHERE token_hash=$1")
        .bind(&token_hash)
        .execute(&state.db)
        .await;
    let _ =
        sqlx::query("UPDATE devices SET name=$1,status='online',last_seen_at=now() WHERE id=$2")
            .bind(device_name)
            .bind(device_id)
            .execute(&state.db)
            .await;
    let (out_tx, mut out_rx) = mpsc::channel::<Message>(1024);
    let connection_id = Uuid::new_v4();
    state.plane.sessions.write().await.insert(
        device_id,
        SessionEntry {
            connection_id,
            tx: out_tx.clone(),
        },
    );
    if let Ok(mut redis) = state.redis.get_multiplexed_tokio_connection().await {
        let _: Result<(), _> = redis.set_ex(format!("online:{device_id}"), "1", 60).await;
    }
    let tunnels = load_specs(&state.db, device_id).await;
    let _ = out_tx
        .send(Message::Text(
            String::from_utf8(
                encode(&ControlMessage::Registered {
                    device_id: device_id.to_string(),
                    tunnels,
                })
                .unwrap(),
            )
            .unwrap()
            .into(),
        ))
        .await;
    // Push the current bandwidth cap so the agent throttles its own outbound
    // data at the source; otherwise fast local traffic can saturate the shared
    // control WebSocket and starve keepalives/control messages.
    let bandwidth_config = ControlMessage::BandwidthConfig {
        mbps: state.bandwidth.current_mbps(),
    };
    if let Ok(payload) = encode(&bandwidth_config) {
        let _ = out_tx
            .send(Message::Text(
                String::from_utf8_lossy(&payload).into_owned().into(),
            ))
            .await;
    }
    let writer = tokio::spawn(async move {
        while let Some(message) = out_rx.recv().await {
            if sink.send(message).await.is_err() {
                break;
            }
        }
    });
    while let Some(Ok(message)) = source.next().await {
        match message {
            Message::Text(text) => {
                if let Ok(ControlMessage::Heartbeat { latency_ms, .. }) = decode(text.as_bytes()) {
                    let _ = sqlx::query(
                        "UPDATE devices SET latency_ms=$1,last_seen_at=now(),status='online' WHERE id=$2",
                    )
                    .bind(latency_ms as i32)
                    .bind(device_id)
                    .execute(&state.db)
                    .await;
                    // Refresh the online marker on every heartbeat so a healthy
                    // device never expires from the Redis view.
                    if let Ok(mut redis) = state.redis.get_multiplexed_tokio_connection().await {
                        let _: Result<(), _> =
                            redis.set_ex(format!("online:{device_id}"), "1", 60).await;
                    }
                } else if let Ok(ControlMessage::StreamClose { stream_id, .. }) =
                    decode(text.as_bytes())
                {
                    if let Ok(id) = stream_id.parse::<u128>() {
                        state.plane.streams.write().await.remove(&id);
                        state.plane.udp_sessions.write().await.remove(&id);
                    }
                } else if let Ok(ControlMessage::ProbeResult {
                    probe_id,
                    ok,
                    message,
                }) = decode(text.as_bytes())
                {
                    if let Some(tx) = state.probes.write().await.remove(&probe_id) {
                        let _ = tx.send(ProbeOutcome { ok, message });
                    }
                }
            }
            // Binary frames belong on data channels; the control socket only
            // carries text control messages.
            _ => {}
        }
    }
    writer.abort();
    {
        let mut sessions = state.plane.sessions.write().await;
        remove_session_if_owned(&mut sessions, device_id, connection_id);
    }
    drop_invalid_udp_sessions(&state, device_id, connection_id).await;
    teardown_device_data_channels(&state, device_id, connection_id).await;
    let _ = sqlx::query("UPDATE devices SET status='offline' WHERE id=$1")
        .bind(device_id)
        .execute(&state.db)
        .await;
}

async fn data_socket(ws: WebSocketUpgrade, State(state): State<AppState>) -> impl IntoResponse {
    ws.on_upgrade(move |socket| data_channel_loop(socket, state))
}

/// Binds one data WebSocket to the device's current control session, replies
/// with its channel id, then forwards binary frames until the socket drops.
async fn data_channel_loop(socket: WebSocket, state: AppState) {
    let (mut sink, mut source) = socket.split();
    let Some(Ok(Message::Text(first))) = source.next().await else {
        return;
    };
    let Ok(ControlMessage::DataBind { token }) = decode(first.as_bytes()) else {
        return;
    };
    let token_hash = format!("{:x}", sha2::Sha256::digest(token.as_bytes()));
    let device_id: Option<Uuid> = sqlx::query_scalar(
        "SELECT device_id FROM access_tokens WHERE token_hash=$1 AND revoked_at IS NULL AND (expires_at IS NULL OR expires_at>now())",
    )
    .bind(&token_hash)
    .fetch_optional(&state.db)
    .await
    .ok()
    .flatten();
    let Some(device_id) = device_id else {
        return;
    };
    // A data channel is only useful while the device has a live control
    // session; capture that session's id so stale teardown never touches
    // channels opened by a newer connection.
    let Some(connection_id) = state
        .plane
        .sessions
        .read()
        .await
        .get(&device_id)
        .map(|entry| entry.connection_id)
    else {
        return;
    };
    let (out_tx, mut out_rx) = mpsc::channel::<Message>(512);
    let channel_id = {
        let mut pool = state.plane.data_channels.write().await;
        let channels = pool.entry(device_id).or_default();
        if channels.len() as u16 >= state.data_channels_max {
            return;
        }
        let Some(channel_id) =
            (1u16..=state.data_channels_max).find(|id| !channels.contains_key(id))
        else {
            return;
        };
        channels.insert(
            channel_id,
            DataChannel {
                connection_id,
                tx: out_tx.clone(),
            },
        );
        channel_id
    };
    let writer = tokio::spawn(async move {
        while let Some(message) = out_rx.recv().await {
            if sink.send(message).await.is_err() {
                break;
            }
        }
    });
    let bound = ControlMessage::DataBound { channel_id };
    if let Ok(payload) = encode(&bound) {
        let _ = out_tx
            .send(Message::Text(
                String::from_utf8_lossy(&payload).into_owned().into(),
            ))
            .await;
    }
    let reader_state = state.clone();
    let reader = tokio::spawn(async move {
        while let Some(Ok(message)) = source.next().await {
            if let Message::Binary(bytes) = message {
                if let Ok((id, data)) = decode_stream_data(&bytes) {
                    match route_stream_data(&reader_state.plane, id, data).await {
                        RouteOutcome::StreamSaturated(stream_id) => {
                            send_control(
                                &reader_state,
                                device_id,
                                &ControlMessage::StreamClose {
                                    stream_id: stream_id.to_string(),
                                    reason: Some("stream_saturated".into()),
                                },
                            )
                            .await;
                        }
                        RouteOutcome::UdpSessionGone(stream_id) => {
                            send_control(
                                &reader_state,
                                device_id,
                                &ControlMessage::StreamClose {
                                    stream_id: stream_id.to_string(),
                                    reason: Some("udp_session_closed".into()),
                                },
                            )
                            .await;
                        }
                        _ => {}
                    }
                }
            }
        }
        writer.abort();
        let removed = close_channel_streams(&reader_state.plane, device_id, channel_id).await;
        for id in removed {
            send_control(
                &reader_state,
                device_id,
                &ControlMessage::StreamClose {
                    stream_id: id.to_string(),
                    reason: Some("data_channel_lost".into()),
                },
            )
            .await;
        }
        reader_state
            .plane
            .data_channels
            .write()
            .await
            .get_mut(&device_id)
            .map(|channels| channels.remove(&channel_id));
        reader_state
            .plane
            .data_socket_tasks
            .lock()
            .await
            .remove(&(device_id, channel_id));
    });
    state
        .plane
        .data_socket_tasks
        .lock()
        .await
        .insert((device_id, channel_id), reader);
}

async fn bootstrap_device(
    db: &PgPool,
    device_name: &str,
    token_hash: &str,
) -> Result<Uuid, sqlx::Error> {
    let workspace =
        sqlx::query_scalar::<_, Uuid>("SELECT id FROM workspaces ORDER BY created_at LIMIT 1")
            .fetch_one(db)
            .await?;
    let device_id = Uuid::new_v4();
    sqlx::query("INSERT INTO devices(id,workspace_id,name) VALUES($1,$2,$3)")
        .bind(device_id)
        .bind(workspace)
        .bind(device_name)
        .execute(db)
        .await?;
    sqlx::query("INSERT INTO access_tokens(id,device_id,label,token_hash,last_used_at) VALUES($1,$2,'bootstrap',$3,now())")
        .bind(Uuid::new_v4())
        .bind(device_id)
        .bind(token_hash)
        .execute(db)
        .await?;
    tracing::info!(%device_id, "bootstrap device registered");
    Ok(device_id)
}
async fn bind_pending_device(
    db: &PgPool,
    token_id: Uuid,
    device_name: &str,
) -> Result<Uuid, sqlx::Error> {
    let mut tx = db.begin().await?;
    let pending: Option<(Uuid, Option<Uuid>)> =
        sqlx::query_as("SELECT id, device_id FROM access_tokens WHERE id=$1 FOR UPDATE")
            .bind(token_id)
            .fetch_optional(&mut *tx)
            .await?;
    match pending {
        Some((_, Some(device_id))) => {
            tx.commit().await?;
            return Ok(device_id);
        }
        None => {
            tx.rollback().await?;
            return Err(sqlx::Error::RowNotFound);
        }
        _ => {}
    }
    let workspace =
        sqlx::query_scalar::<_, Uuid>("SELECT id FROM workspaces ORDER BY created_at LIMIT 1")
            .fetch_one(&mut *tx)
            .await?;
    let device_id = Uuid::new_v4();
    sqlx::query("INSERT INTO devices(id,workspace_id,name) VALUES($1,$2,$3)")
        .bind(device_id)
        .bind(workspace)
        .bind(device_name)
        .execute(&mut *tx)
        .await?;
    sqlx::query("UPDATE access_tokens SET device_id=$1 WHERE id=$2")
        .bind(device_id)
        .bind(token_id)
        .execute(&mut *tx)
        .await?;
    tx.commit().await?;
    tracing::info!(%device_id, "access key bound to new device");
    Ok(device_id)
}
async fn load_specs(db: &PgPool, device_id: Uuid) -> Vec<TunnelSpec> {
    sqlx::query_as::<_,(Uuid,String,String,i32,String,i32,bool,i32)>(
        "SELECT id,name,kind,public_port,local_host,local_port,enabled,max_connections FROM tunnels WHERE device_id=$1 AND enabled",
    )
    .bind(device_id)
    .fetch_all(db)
    .await
    .unwrap_or_default()
    .into_iter()
    .map(|r| TunnelSpec {
        id: r.0.to_string(),
        name: r.1,
        kind: match r.2.as_str() {
            "udp" => TunnelKind::Udp,
            "http" => TunnelKind::Http,
            _ => TunnelKind::Tcp,
        },
        public_port: r.3 as u16,
        local_host: r.4,
        local_port: r.5 as u16,
        enabled: r.6,
        max_connections: r.7 as u16,
    })
    .collect()
}
async fn start_listener(state: AppState, tunnel_id: Uuid) -> Result<(), String> {
    if state.listeners.read().await.contains_key(&tunnel_id) {
        return Ok(());
    }
    let tunnel = get_tunnel(&state.db, tunnel_id)
        .await
        .map_err(|e| e.to_string())?;
    if tunnel.kind == "udp" {
        let socket = UdpSocket::bind(("0.0.0.0", tunnel.public_port as u16))
            .await
            .map_err(|e| e.to_string())?;
        let listener_state = state.clone();
        let handle = tokio::spawn(async move {
            bridge_public_udp(listener_state, tunnel, socket).await;
        });
        state.listeners.write().await.insert(tunnel_id, handle);
        return Ok(());
    }
    let listener = TcpListener::bind(("0.0.0.0", tunnel.public_port as u16))
        .await
        .map_err(|e| e.to_string())?;
    let listener_state = state.clone();
    let handle = tokio::spawn(async move {
        loop {
            let Ok((socket, _)) = listener.accept().await else {
                break;
            };
            let st = listener_state.clone();
            let t = tunnel.clone();
            tokio::spawn(async move {
                bridge_public_connection(st, t, socket).await;
            });
        }
    });
    state.listeners.write().await.insert(tunnel_id, handle);
    Ok(())
}
async fn bridge_public_connection(
    state: AppState,
    tunnel: TunnelRecord,
    socket: tokio::net::TcpStream,
) {
    if !state.accepting.load(Ordering::Relaxed) {
        return;
    }
    let Some(session) = state
        .plane
        .sessions
        .read()
        .await
        .get(&tunnel.device_id)
        .cloned()
    else {
        return;
    };
    let Some(channel_id) = pick_data_channel(&state, tunnel.device_id).await else {
        return;
    };
    let Some(channel) = state
        .plane
        .data_channels
        .read()
        .await
        .get(&tunnel.device_id)
        .and_then(|channels| channels.get(&channel_id))
        .cloned()
    else {
        return;
    };
    let id = Uuid::new_v4().as_u128();
    let (mut reader, mut writer) = socket.into_split();
    let (incoming_tx, mut incoming_rx) = mpsc::channel::<Vec<u8>>(128);
    state.plane.streams.write().await.insert(
        id,
        StreamEntry {
            device_id: tunnel.device_id,
            data_channel: channel_id,
            tx: incoming_tx,
        },
    );
    if session
        .tx
        .send(Message::Text(
            String::from_utf8(
                encode(&ControlMessage::StreamOpen {
                    stream_id: id.to_string(),
                    tunnel_id: tunnel.id.to_string(),
                    data_channel: channel_id,
                })
                .unwrap(),
            )
            .unwrap()
            .into(),
        ))
        .await
        .is_err()
    {
        state.plane.streams.write().await.remove(&id);
        return;
    }
    let out = channel.tx;
    let limiter = state.bandwidth.clone();
    let inbound = tokio::spawn(async move {
        while let Some(data) = incoming_rx.recv().await {
            limiter.acquire(data.len()).await;
            if writer.write_all(&data).await.is_err() {
                break;
            }
        }
    });
    let mut buf = [0_u8; 16 * 1024];
    loop {
        match tokio::io::AsyncReadExt::read(&mut reader, &mut buf).await {
            Ok(0) | Err(_) => break,
            Ok(n) => {
                state.bandwidth.acquire(n).await;
                let Ok(frame) = encode_stream_data(id, &buf[..n]) else {
                    break;
                };
                // This bridge task may wait for the device's outbound queue or
                // the bandwidth budget; it never blocks the control loop, and
                // TCP must not drop bytes, so queue here instead of closing.
                if out.send(Message::Binary(frame.into())).await.is_err() {
                    break;
                }
            }
        }
    }
    let _ = session.tx.try_send(Message::Text(
        String::from_utf8(
            encode(&ControlMessage::StreamClose {
                stream_id: id.to_string(),
                reason: None,
            })
            .unwrap(),
        )
        .unwrap()
        .into(),
    ));
    state.plane.streams.write().await.remove(&id);
    inbound.abort();
}

/// Stops a tunnel listener and drops any UDP sessions bound to it.
async fn remove_listener(state: &AppState, tunnel_id: Uuid) {
    if let Some(task) = state.listeners.write().await.remove(&tunnel_id) {
        task.abort();
    }
    let stale: Vec<(u128, Uuid)> = state
        .plane
        .udp_sessions
        .read()
        .await
        .iter()
        .filter(|(_, session)| session.tunnel_id == tunnel_id)
        .map(|(id, session)| (*id, session.device_id))
        .collect();
    for (id, device_id) in stale {
        state.plane.udp_sessions.write().await.remove(&id);
        send_control(
            &state,
            device_id,
            &ControlMessage::StreamClose {
                stream_id: id.to_string(),
                reason: Some("tunnel_disabled".into()),
            },
        )
        .await;
    }
}

/// Drops every UDP session for a device, typically after its control channel
/// closed or a frame could no longer be delivered. Only sessions belonging to
/// `connection_id` are removed so a stale control loop cannot drop sessions
/// created by a newer connection.
async fn drop_invalid_udp_sessions(state: &AppState, device_id: Uuid, connection_id: Uuid) {
    let stale: Vec<u128> = state
        .plane
        .udp_sessions
        .read()
        .await
        .iter()
        .filter(|(_, session)| {
            session.device_id == device_id && session.connection_id == connection_id
        })
        .map(|(id, _)| *id)
        .collect();
    for id in stale {
        state.plane.udp_sessions.write().await.remove(&id);
    }
}

/// Receives UDP datagrams from public clients and relays them over the agent's
/// control channel. One session is kept per remote client address and each
/// session maps to a u128 stream id in the existing frame protocol.
async fn bridge_public_udp(state: AppState, tunnel: TunnelRecord, socket: UdpSocket) {
    let socket = Arc::new(socket);
    let mut buffer = [0_u8; 65536];
    let idle_secs = state.udp_session_idle_secs;
    let mut cleanup = tokio::time::interval(StdDuration::from_secs(idle_secs.min(60).max(10)));
    cleanup.tick().await;
    loop {
        tokio::select! {
            result = socket.recv_from(&mut buffer) => {
                let Ok((size, peer)) = result else {
                    break;
                };
                if !state.accepting.load(Ordering::Relaxed) {
                    continue;
                }
                state.bandwidth.acquire(size).await;
                let stream_id = {
                    let sessions = state.plane.udp_sessions.read().await;
                    sessions
                        .iter()
                        .find(|(_, session)| {
                            session.tunnel_id == tunnel.id && session.peer == peer
                        })
                        .map(|(id, _)| *id)
                };
                let stream_id = match stream_id {
                    Some(id) => id,
                    None => {
                        let active = state
                            .plane
                            .udp_sessions
                            .read()
                            .await
                            .values()
                            .filter(|session| session.tunnel_id == tunnel.id)
                            .count();
                        if active >= tunnel.max_connections as usize {
                            continue;
                        }
                        let Some(session) = state
                            .plane
                            .sessions
                            .read()
                            .await
                            .get(&tunnel.device_id)
                            .cloned()
                        else {
                            continue;
                        };
                        let Some(channel_id) = pick_data_channel(&state, tunnel.device_id).await
                        else {
                            continue;
                        };
                        let id = Uuid::new_v4().as_u128();
                        let open = ControlMessage::StreamOpen {
                            stream_id: id.to_string(),
                            tunnel_id: tunnel.id.to_string(),
                            data_channel: channel_id,
                        };
                        let Ok(payload) = encode(&open) else {
                            continue;
                        };
                        if session
                            .tx
                            .try_send(Message::Text(
                                String::from_utf8_lossy(&payload).into_owned().into(),
                            ))
                            .is_err()
                        {
                            continue;
                        }
                        let (outbox_tx, mut outbox_rx) = mpsc::channel::<Vec<u8>>(512);
                        let send_socket = socket.clone();
                        let send_peer = peer;
                        let limiter = state.bandwidth.clone();
                        tokio::spawn(async move {
                            while let Some(data) = outbox_rx.recv().await {
                                limiter.acquire(data.len()).await;
                                if send_socket.send_to(&data, send_peer).await.is_err() {
                                    break;
                                }
                            }
                        });
                        state.plane.udp_sessions.write().await.insert(
                            id,
                            UdpSession {
                                device_id: tunnel.device_id,
                                connection_id: session.connection_id,
                                tunnel_id: tunnel.id,
                                data_channel: channel_id,
                                peer,
                                outbox: outbox_tx,
                                last_seen: Instant::now(),
                            },
                        );
                        id
                    }
                };
                if let Some(current) = state.plane.udp_sessions.write().await.get_mut(&stream_id) {
                    current.last_seen = Instant::now();
                }
                let Ok(frame) = encode_stream_data(stream_id, &buffer[..size]) else {
                    continue;
                };
                let Some(session) = state
                    .plane
                    .udp_sessions
                    .read()
                    .await
                    .get(&stream_id)
                    .cloned()
                else {
                    continue;
                };
                let Some(channel) = state
                    .plane
                    .data_channels
                    .read()
                    .await
                    .get(&tunnel.device_id)
                    .and_then(|channels| channels.get(&session.data_channel))
                    .cloned()
                else {
                    continue;
                };
                match channel.tx.try_send(Message::Binary(frame.into())) {
                    Ok(()) => {}
                    Err(mpsc::error::TrySendError::Closed(_)) => {
                        drop_invalid_udp_sessions(&state, tunnel.device_id, session.connection_id)
                            .await;
                    }
                    Err(mpsc::error::TrySendError::Full(_)) => {
                        // UDP tolerates loss; drop the datagram.
                    }
                }
            }
            _ = cleanup.tick() => {
                let now = Instant::now();
                let expired: Vec<u128> = state
                    .plane
                    .udp_sessions
                    .read()
                    .await
                    .iter()
                    .filter(|(_, session)| {
                        session.tunnel_id == tunnel.id
                            && now.duration_since(session.last_seen)
                                > StdDuration::from_secs(idle_secs)
                    })
                    .map(|(id, _)| *id)
                    .collect();
                for id in expired {
                    state.plane.udp_sessions.write().await.remove(&id);
                    send_control(
                        &state,
                        tunnel.device_id,
                        &ControlMessage::StreamClose {
                            stream_id: id.to_string(),
                            reason: Some("udp_session_timeout".into()),
                        },
                    )
                    .await;
                }
            }
        }
    }
}
