use argon2::PasswordHasher;
use axum::{
    Json, Router,
    extract::{
        Path, Query, State,
        ws::{Message, WebSocket, WebSocketUpgrade},
    },
    http::{HeaderMap, StatusCode, header},
    response::IntoResponse,
    routing::{delete, get, post, put},
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
        atomic::{AtomicU64, AtomicUsize, Ordering},
    },
    time::{Duration as StdDuration, Instant},
};
use tokio::{
    io::AsyncWriteExt,
    net::{TcpListener, UdpSocket},
    sync::{Mutex, Notify, RwLock, mpsc, oneshot},
};
use tower_http::{cors::CorsLayer, trace::TraceLayer};
use tunnel_protocol::{
    AgentSettings, ControlMessage, PROTOCOL_VERSION, TCP_CHUNK_SIZE, TunnelKind, TunnelSpec,
    decode, decode_stream_data, encode, encode_stream_data,
};
use uuid::Uuid;

/// Enrollment pairing: the agent shows an 8-character code drawn from an
/// unambiguous alphabet; the admin enters it in the management console. The
/// server only stores the SHA-256 hash and keeps the code single-use.
const ENROLL_CODE_LEN: usize = 8;
const ENROLL_CODE_ALPHABET: &[u8] = b"23456789ABCDEFGHJKMNPQRSTUVWXYZ";
const ENROLL_TTL_MINUTES: i64 = 15;

/// Interval at which the background task persists in-memory heartbeats to the
/// database and refreshes the Redis online markers. Kept short enough that
/// online status never drifts more than a couple of minutes.
const HEARTBEAT_FLUSH_SECS: u64 = 30;
/// Entries older than this are pruned from the in-memory heartbeat map. Agent
/// heartbeats can be configured up to 60s apart, so this is three missed
/// heartbeats; pruning only stops refreshes, it never touches live sessions.
const HEARTBEAT_STALE_SECS: u64 = 180;
/// Interval at which a background task re-checks enabled tunnels and restarts
/// listeners that exited after an accept/bind error.
const LISTENER_RECONCILE_SECS: u64 = 30;

#[derive(Clone)]
struct AppState {
    db: PgPool,
    redis: redis::Client,
    /// Reused Redis connection for the heartbeat flusher. `None` while Redis
    /// is unavailable; the flusher retries on the next tick.
    redis_conn: Arc<Mutex<Option<redis::aio::MultiplexedConnection>>>,
    jwt_secret: Arc<String>,
    admin_token_ttl_hours: i64,
    bootstrap_agent_token_hash: Option<String>,
    listeners: Arc<RwLock<HashMap<Uuid, ListenerEntry>>>,
    udp_session_idle_secs: u64,
    probes: Arc<RwLock<HashMap<String, oneshot::Sender<ProbeOutcome>>>>,
    bandwidth: BandwidthLimiter,
    tunnel_port_start: u16,
    tunnel_port_end: u16,
    data_channels_max: u16,
    shutdown_drain_secs: u64,
    accepting: Arc<std::sync::atomic::AtomicBool>,
    plane: DataPlane,
    pending_enrollments: Arc<RwLock<HashMap<Uuid, PendingEnrollment>>>,
}

/// A running tunnel listener task plus the generation it was started with.
/// The generation lets an exiting task remove only its own handle instead of
/// one installed by a newer `start_listener` after a fast restart.
struct ListenerEntry {
    generation: u64,
    task: tokio::task::JoinHandle<()>,
}

/// In-memory half of a pending enrollment: the live control socket that showed
/// the code, waiting for the admin's approve/deny decision.
struct PendingEnrollment {
    code_hash: String,
    expires_at: chrono::DateTime<Utc>,
    tx: oneshot::Sender<EnrollmentDecision>,
}

enum EnrollmentDecision {
    Approved { token: String, device_id: Uuid },
    Denied,
    Expired,
}

/// In-memory data-plane state shared by the control socket and every data
/// socket. Kept separate from AppState so routing and cleanup logic can be
/// unit tested without a database.
#[derive(Clone)]
struct DataPlane {
    sessions: Arc<RwLock<HashMap<Uuid, SessionEntry>>>,
    streams: Arc<RwLock<HashMap<u128, StreamEntry>>>,
    udp_sessions: Arc<RwLock<HashMap<u128, UdpSession>>>,
    /// Per (device, data channel) count of live TCP streams and UDP sessions.
    /// `pick_data_channel` reads these counters instead of scanning every
    /// stream, keeping channel selection O(channels) per new connection.
    channel_loads: Arc<std::sync::Mutex<HashMap<(Uuid, u16), Arc<AtomicUsize>>>>,
    /// Per-tunnel UDP peer index so each incoming datagram hits its session
    /// by `SocketAddr` directly instead of scanning all sessions.
    udp_peers: Arc<RwLock<HashMap<Uuid, HashMap<SocketAddr, u128>>>>,
    data_channels: Arc<RwLock<HashMap<Uuid, HashMap<u16, DataChannel>>>>,
    data_socket_tasks: Arc<Mutex<HashMap<(Uuid, u16), tokio::task::JoinHandle<()>>>>,
    heartbeats: Arc<RwLock<HashMap<Uuid, HeartbeatEntry>>>,
    /// Wakes bridge tasks waiting for a data channel whenever a device's
    /// channel set changes (bind, drop, or teardown).
    data_channel_signal: Arc<Notify>,
    /// Wakes bridge tasks waiting for a data channel whenever a control
    /// session is inserted or removed.
    session_signal: Arc<Notify>,
}

impl Default for DataPlane {
    fn default() -> Self {
        Self {
            sessions: Arc::new(RwLock::new(HashMap::new())),
            streams: Arc::new(RwLock::new(HashMap::new())),
            udp_sessions: Arc::new(RwLock::new(HashMap::new())),
            channel_loads: Arc::new(std::sync::Mutex::new(HashMap::new())),
            udp_peers: Arc::new(RwLock::new(HashMap::new())),
            data_channels: Arc::new(RwLock::new(HashMap::new())),
            data_socket_tasks: Arc::new(Mutex::new(HashMap::new())),
            heartbeats: Arc::new(RwLock::new(HashMap::new())),
            data_channel_signal: Arc::new(Notify::new()),
            session_signal: Arc::new(Notify::new()),
        }
    }
}

/// One live control session for a device. The connection id lets a stale
/// control loop (left over from a previous connection) avoid removing the
/// session registered by a newer connection during a fast reconnect.
#[derive(Clone)]
struct SessionEntry {
    connection_id: Uuid,
    tx: mpsc::Sender<Message>,
}

/// Latest heartbeat seen on a control session, kept in memory so the control
/// read loop never performs database/Redis IO. A background flusher persists
/// it in batches; the connection id guards cleanup after a fast reconnect.
#[derive(Clone)]
struct HeartbeatEntry {
    connection_id: Uuid,
    latency_ms: i32,
    last_seen: Instant,
}

/// A data WebSocket bound to a device's current control session. `tx` is the
/// queue drained by that socket's writer; new streams are assigned to one of
/// these channels by `pick_data_channel`.
#[derive(Clone)]
struct DataChannel {
    connection_id: Uuid,
    tx: mpsc::Sender<Message>,
}

/// One stream's share of its data channel's shared writer queue. `outstanding`
/// counts frames queued but not yet forwarded by the channel writer; when it
/// reaches `STREAM_CHANNEL_QUOTA` the stream's bridge waits, so a single bulk
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

/// A live TCP stream mapped to the data channel it was assigned to.
#[derive(Clone)]
struct StreamEntry {
    device_id: Uuid,
    tunnel_id: Uuid,
    data_channel: u16,
    tx: mpsc::Sender<Vec<u8>>,
    slot: Arc<Mutex<StreamSlot>>,
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
    /// TCP stream queue stayed full past the send timeout; the stream must be
    /// closed so a wedged peer cannot stall the data channel forever.
    StreamSendTimeout(u128),
    /// TCP stream queue closed while enqueuing; the stream must be closed.
    StreamChannelClosed(u128),
    /// UDP session outbox was closed; the session entry is gone.
    UdpSessionGone(u128),
}

/// Upper bound on how long routing waits for one TCP frame to enter a
/// stream's bounded queue. Waiting (instead of dropping or closing the
/// stream) turns queue pressure into TCP backpressure; the cap only exists so
/// a wedged peer cannot stall the data channel indefinitely.
const TCP_SEND_TIMEOUT: StdDuration = StdDuration::from_secs(30);

/// How long a public TCP connection waits for a data channel after the
/// device's control session registered. Bounded so a reconnect window cannot
/// pile waiting connections up indefinitely.
const DATA_CHANNEL_WAIT: StdDuration = StdDuration::from_secs(3);

/// How long `StreamOpen` waits for the control queue to drain before the new
/// connection is rejected. Short enough that a congested control socket never
/// stalls bridge tasks for long.
const STREAM_OPEN_SEND_TIMEOUT: StdDuration = StdDuration::from_millis(500);

/// Frames buffered per TCP stream before backpressure applies; 64 x 64KiB
/// keeps the worst-case per-stream queue at 4MiB.
const STREAM_QUEUE_FRAMES: usize = 64;

/// Frames buffered per data channel; 128 x 64KiB keeps the worst-case shared
/// queue at 8MiB, matching the old 512 x 16KiB budget.
const DATA_CHANNEL_QUEUE_FRAMES: usize = 128;

/// Max frames one stream may have waiting in its data channel's shared writer
/// queue. 16 x 64KiB bounds the head-of-line delay a bulk stream can impose
/// on other streams sharing the same channel.
const STREAM_CHANNEL_QUOTA: usize = 16;
/// Minimum gap between "heartbeat echo dropped" warnings so a saturated data
/// channel logs the symptom without flooding the log.
const ECHO_DROP_WARN_SECS: u64 = 10;

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

/// Removes a heartbeat entry only when it still belongs to `connection_id`,
/// mirroring the session cleanup so a stale control loop can never drop the
/// heartbeat state of a newer connection.
fn remove_heartbeat_if_owned(
    heartbeats: &mut HashMap<Uuid, HeartbeatEntry>,
    device_id: Uuid,
    connection_id: Uuid,
) -> bool {
    match heartbeats.get(&device_id) {
        Some(entry) if entry.connection_id == connection_id => {
            heartbeats.remove(&device_id);
            true
        }
        _ => false,
    }
}

impl DataPlane {
    /// Live TCP streams + UDP sessions currently assigned to one data channel.
    fn channel_load(&self, device_id: Uuid, channel_id: u16) -> usize {
        let loads = self.channel_loads.lock().unwrap();
        loads
            .get(&(device_id, channel_id))
            .map(|counter| counter.load(Ordering::Relaxed))
            .unwrap_or(0)
    }

    fn increment_channel_load(&self, device_id: Uuid, channel_id: u16) {
        let counter = {
            let mut loads = self.channel_loads.lock().unwrap();
            loads
                .entry((device_id, channel_id))
                .or_insert_with(|| Arc::new(AtomicUsize::new(0)))
                .clone()
        };
        counter.fetch_add(1, Ordering::Relaxed);
    }

    fn decrement_channel_load(&self, device_id: Uuid, channel_id: u16) {
        let counter = {
            let mut loads = self.channel_loads.lock().unwrap();
            loads
                .entry((device_id, channel_id))
                .or_insert_with(|| Arc::new(AtomicUsize::new(0)))
                .clone()
        };
        let _ = counter.fetch_update(Ordering::Relaxed, Ordering::Relaxed, |value| {
            Some(value.saturating_sub(1))
        });
    }
}

/// Inserts a UDP session and keeps the channel-load counter and the
/// per-tunnel peer index in sync. Bookkeeping is committed before the session
/// becomes visible, so a concurrent removal either finds the fully-registered
/// session (and cleans up all three structures) or finds nothing.
async fn insert_udp_session(plane: &DataPlane, id: u128, session: UdpSession) {
    plane.increment_channel_load(session.device_id, session.data_channel);
    plane
        .udp_peers
        .write()
        .await
        .entry(session.tunnel_id)
        .or_default()
        .insert(session.peer, id);
    plane.udp_sessions.write().await.insert(id, session);
}

/// Removes a UDP session together with its peer-index entry and channel-load
/// counter. Safe to call for ids that are already gone.
async fn remove_udp_session(plane: &DataPlane, id: u128) {
    let session = plane.udp_sessions.write().await.remove(&id);
    if let Some(session) = session {
        plane.decrement_channel_load(session.device_id, session.data_channel);
        let mut peers = plane.udp_peers.write().await;
        if let Some(peers_for_tunnel) = peers.get_mut(&session.tunnel_id) {
            peers_for_tunnel.remove(&session.peer);
            if peers_for_tunnel.is_empty() {
                peers.remove(&session.tunnel_id);
            }
        }
    }
}

/// Routes one incoming data frame (from any data socket) to its destination.
/// TCP frames wait in the stream's bounded queue so backpressure reaches the
/// sender; UDP datagrams are dropped when their queue is full instead.
async fn route_stream_data(plane: &DataPlane, id: u128, data: &[u8]) -> RouteOutcome {
    route_stream_data_with_timeout(plane, id, data, TCP_SEND_TIMEOUT).await
}

/// Atomically counts the active TCP streams for one tunnel and registers a
/// new stream when the tunnel still has capacity. Returns false (and inserts
/// nothing) once `max_connections` streams are active; callers then reject
/// the public connection without sending `StreamOpen`.
async fn try_register_stream(
    plane: &DataPlane,
    id: u128,
    device_id: Uuid,
    tunnel_id: Uuid,
    data_channel: u16,
    tx: mpsc::Sender<Vec<u8>>,
    max_connections: usize,
) -> bool {
    let mut streams = plane.streams.write().await;
    let active = streams
        .values()
        .filter(|entry| entry.device_id == device_id && entry.tunnel_id == tunnel_id)
        .count();
    if active >= max_connections {
        return false;
    }
    streams.insert(
        id,
        StreamEntry {
            device_id,
            tunnel_id,
            data_channel,
            tx,
            slot: Arc::new(Mutex::new(StreamSlot::default())),
        },
    );
    // Count while still holding the streams lock so a concurrent removal can
    // never observe the entry without the counter having been incremented.
    plane.increment_channel_load(device_id, data_channel);
    true
}

/// Waits until the stream has fewer than `STREAM_CHANNEL_QUOTA` frames waiting
/// in the channel writer queue, then reserves one slot. Returns false if the
/// stream entry is removed while waiting (the bridge should stop).
async fn acquire_stream_slot(plane: &DataPlane, slot: &Arc<Mutex<StreamSlot>>, id: u128) -> bool {
    loop {
        if plane.streams.read().await.get(&id).is_none() {
            return false;
        }
        let notify = {
            let mut state = slot.lock().await;
            if state.outstanding < STREAM_CHANNEL_QUOTA {
                state.outstanding += 1;
                return true;
            }
            state.notify.clone()
        };
        notify.notified().await;
        if plane.streams.read().await.get(&id).is_none() {
            return false;
        }
    }
}

/// Releases one reserved slot after the channel writer dequeued the frame and
/// wakes the stream's bridge so it can enqueue more.
async fn release_stream_slot(plane: &DataPlane, id: u128) {
    let slot = {
        let streams = plane.streams.read().await;
        streams.get(&id).map(|entry| entry.slot.clone())
    };
    if let Some(slot) = slot {
        let mut state = slot.lock().await;
        state.outstanding = state.outstanding.saturating_sub(1);
        state.notify.notify_waiters();
    }
}

/// Removes a stream entry and wakes its bridge if it is waiting on the
/// channel-queue quota, so closing the stream cannot strand the bridge.
async fn remove_stream_entry(plane: &DataPlane, id: u128) {
    let entry = {
        let mut streams = plane.streams.write().await;
        streams.remove(&id)
    };
    if let Some(entry) = entry {
        plane.decrement_channel_load(entry.device_id, entry.data_channel);
        let mut state = entry.slot.lock().await;
        state.outstanding = 0;
        state.notify.notify_waiters();
    }
}

async fn route_stream_data_with_timeout(
    plane: &DataPlane,
    id: u128,
    data: &[u8],
    timeout: StdDuration,
) -> RouteOutcome {
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
                remove_udp_session(plane, id).await;
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
            Some(tx) => match tokio::time::timeout(timeout, tx.send(data.to_vec())).await {
                Ok(Ok(())) => RouteOutcome::Ok,
                Ok(Err(_)) => {
                    remove_stream_entry(plane, id).await;
                    RouteOutcome::StreamChannelClosed(id)
                }
                Err(_) => {
                    remove_stream_entry(plane, id).await;
                    RouteOutcome::StreamSendTimeout(id)
                }
            },
            None => RouteOutcome::Ok,
        }
    }
}

/// Sends a control message to the device's current session without blocking.
/// A full or closed control queue counts as "control unavailable" and returns
/// false, so callers (including the data-channel read loop) never stall on a
/// congested control WebSocket.
async fn send_control(state: &AppState, device_id: Uuid, message: &ControlMessage) -> bool {
    let Some(session) = state.plane.sessions.read().await.get(&device_id).cloned() else {
        return false;
    };
    send_control_to_session(&session, message, None).await
}

/// Encodes and sends one control message to a specific session. Tries without
/// blocking first; when `timeout` is set and the queue is full, waits at most
/// that long for space. Returns false when the queue is full past the timeout
/// or the session is closed.
async fn send_control_to_session(
    session: &SessionEntry,
    message: &ControlMessage,
    timeout: Option<StdDuration>,
) -> bool {
    let Ok(payload) = encode(message) else {
        return false;
    };
    let text = Message::Text(String::from_utf8_lossy(&payload).into_owned().into());
    if session.tx.try_send(text.clone()).is_ok() {
        return true;
    }
    let Some(timeout) = timeout else {
        return false;
    };
    matches!(
        tokio::time::timeout(timeout, session.tx.send(text)).await,
        Ok(Ok(()))
    )
}

/// Picks the data channel with the fewest active streams, preferring the
/// lowest channel id on ties. Only channels bound to the device's current
/// control session are eligible, so a stale channel left over from a fast
/// reconnect is never handed out. Returns None while the device has no
/// control session or no bound channel (for example during a reconnect).
async fn pick_data_channel(plane: &DataPlane, device_id: Uuid) -> Option<u16> {
    let current_connection_id = {
        let sessions = plane.sessions.read().await;
        sessions.get(&device_id).map(|entry| entry.connection_id)
    };
    let channels: Vec<u16> = {
        let pool = plane.data_channels.read().await;
        pool.get(&device_id)
            .map(|channels| {
                channels
                    .iter()
                    .filter(|(_, channel)| Some(channel.connection_id) == current_connection_id)
                    .map(|(id, _)| *id)
                    .collect()
            })
            .unwrap_or_default()
    };
    if channels.is_empty() {
        return None;
    }
    let mut best: Option<(usize, u16)> = None;
    for channel_id in channels {
        let load = plane.channel_load(device_id, channel_id);
        if best.map(|(best_load, _)| load < best_load).unwrap_or(true) {
            best = Some((load, channel_id));
        }
    }
    best.map(|(_, channel_id)| channel_id)
}

/// Waits up to `DATA_CHANNEL_WAIT` for the device's current control session to
/// gain at least one data channel. Returns None on timeout or when the
/// control session disappears while waiting.
async fn wait_for_data_channel(plane: &DataPlane, device_id: Uuid) -> Option<u16> {
    wait_for_data_channel_with_timeout(plane, device_id, DATA_CHANNEL_WAIT).await
}

async fn wait_for_data_channel_with_timeout(
    plane: &DataPlane,
    device_id: Uuid,
    timeout: StdDuration,
) -> Option<u16> {
    if let Some(channel_id) = pick_data_channel(plane, device_id).await {
        return Some(channel_id);
    }
    let deadline = tokio::time::Instant::now() + timeout;
    loop {
        let channel_signal = plane.data_channel_signal.notified();
        let session_signal = plane.session_signal.notified();
        tokio::select! {
            _ = channel_signal => {}
            _ = session_signal => {}
            _ = tokio::time::sleep_until(deadline) => return None,
        }
        if plane.sessions.read().await.get(&device_id).is_none() {
            return None;
        }
        if let Some(channel_id) = pick_data_channel(plane, device_id).await {
            return Some(channel_id);
        }
    }
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
        remove_stream_entry(plane, *id).await;
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
        remove_udp_session(plane, *id).await;
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
    let mut removed_any = false;
    for channel_id in channels {
        removed_any = true;
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
    if removed_any {
        state.plane.data_channel_signal.notify_waiters();
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

/// Per-device token buckets that throttle the public -> agent direction; the
/// agent throttles agent -> server at its source, so no direction is ever
/// charged twice. Each device keeps its own bucket at the configured rate, so
/// frames of different devices never serialize on one global mutex. A rate
/// of 0 disables throttling.
#[derive(Clone)]
struct BandwidthLimiter {
    mbps: Arc<AtomicU64>,
    buckets: Arc<RwLock<HashMap<Uuid, Arc<tokio::sync::Mutex<BucketState>>>>>,
}

struct BucketState {
    tokens: f64,
    last: Instant,
}

impl BandwidthLimiter {
    fn new(mbps: u64) -> Self {
        Self {
            mbps: Arc::new(AtomicU64::new(mbps)),
            buckets: Arc::new(RwLock::new(HashMap::new())),
        }
    }

    fn current_mbps(&self) -> u64 {
        self.mbps.load(Ordering::Relaxed)
    }

    fn set_mbps(&self, mbps: u64) {
        self.mbps.store(mbps, Ordering::Relaxed);
    }

    async fn acquire(&self, device_id: Uuid, bytes: usize) {
        let mbps = self.mbps.load(Ordering::Relaxed);
        if mbps == 0 {
            return;
        }
        let bucket = self.bucket(device_id).await;
        let mut state = bucket.lock().await;
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
            state = bucket.lock().await;
        }
    }

    async fn bucket(&self, device_id: Uuid) -> Arc<tokio::sync::Mutex<BucketState>> {
        if let Some(bucket) = self.buckets.read().await.get(&device_id).cloned() {
            return bucket;
        }
        let mut buckets = self.buckets.write().await;
        buckets
            .entry(device_id)
            .or_insert_with(|| {
                let mbps = self.mbps.load(Ordering::Relaxed);
                Arc::new(tokio::sync::Mutex::new(BucketState {
                    tokens: mbps as f64 * 1_000_000.0 / 8.0,
                    last: Instant::now(),
                }))
            })
            .clone()
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[tokio::test]
    async fn bandwidth_limiter_caps_throughput() {
        let limiter = BandwidthLimiter::new(1);
        let device = Uuid::new_v4();
        let started = Instant::now();
        let mut sent = 0usize;
        // Four seconds worth of budget: the first second is the burst, the
        // remaining three seconds must be paced by the token bucket.
        while sent < 500_000 {
            limiter.acquire(device, 1_250).await;
            sent += 1_250;
        }
        let elapsed = started.elapsed().as_secs_f64();
        assert!(elapsed >= 2.5 && elapsed < 6.0, "elapsed {elapsed}");
    }

    #[tokio::test]
    async fn bandwidth_limiter_disabled_passes_through() {
        let limiter = BandwidthLimiter::new(1);
        let device = Uuid::new_v4();
        limiter.set_mbps(0);
        let started = Instant::now();
        for _ in 0..100 {
            limiter.acquire(device, 64 * 1024).await;
        }
        assert!(started.elapsed().as_millis() < 500);
    }

    #[tokio::test]
    async fn bandwidth_limiter_per_device_buckets_do_not_share_tokens() {
        let limiter = BandwidthLimiter::new(1);
        let device_a = Uuid::new_v4();
        let device_b = Uuid::new_v4();
        let started = Instant::now();
        // Each device starts with its own full burst; consuming A's burst
        // must not consume B's, so B's burst-sized acquire returns at once.
        limiter.acquire(device_a, 125_000).await;
        limiter.acquire(device_b, 125_000).await;
        assert!(
            started.elapsed() < StdDuration::from_millis(200),
            "per-device buckets must not share tokens"
        );
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
    async fn stale_control_cleanup_keeps_new_heartbeat() {
        let device = Uuid::new_v4();
        let old_connection = Uuid::new_v4();
        let new_connection = Uuid::new_v4();
        let mut heartbeats = HashMap::new();
        heartbeats.insert(
            device,
            HeartbeatEntry {
                connection_id: new_connection,
                latency_ms: 12,
                last_seen: Instant::now(),
            },
        );
        // A stale control loop finishing after a fast reconnect must not
        // remove the heartbeat state of the newer connection.
        assert!(!remove_heartbeat_if_owned(
            &mut heartbeats,
            device,
            old_connection
        ));
        assert!(heartbeats.contains_key(&device));
        assert!(remove_heartbeat_if_owned(
            &mut heartbeats,
            device,
            new_connection
        ));
        assert!(!heartbeats.contains_key(&device));
    }

    #[tokio::test]
    async fn wait_for_data_channel_returns_existing_channel() {
        let plane = DataPlane::default();
        let device = Uuid::new_v4();
        let connection = Uuid::new_v4();
        let (session_tx, _session_rx) = mpsc::channel::<Message>(8);
        plane.sessions.write().await.insert(
            device,
            SessionEntry {
                connection_id: connection,
                tx: session_tx,
            },
        );
        let (channel_tx, _channel_rx) = mpsc::channel::<Message>(8);
        plane.data_channels.write().await.insert(
            device,
            HashMap::from([(
                1,
                DataChannel {
                    connection_id: connection,
                    tx: channel_tx,
                },
            )]),
        );
        assert_eq!(wait_for_data_channel(&plane, device).await, Some(1));
    }

    #[tokio::test]
    async fn wait_for_data_channel_waits_for_bind() {
        let plane = DataPlane::default();
        let device = Uuid::new_v4();
        let connection = Uuid::new_v4();
        let (session_tx, _session_rx) = mpsc::channel::<Message>(8);
        plane.sessions.write().await.insert(
            device,
            SessionEntry {
                connection_id: connection,
                tx: session_tx,
            },
        );
        let bind_plane = plane.clone();
        let bind = tokio::spawn(async move {
            tokio::time::sleep(StdDuration::from_millis(100)).await;
            let (channel_tx, _channel_rx) = mpsc::channel::<Message>(8);
            bind_plane.data_channels.write().await.insert(
                device,
                HashMap::from([(
                    1,
                    DataChannel {
                        connection_id: connection,
                        tx: channel_tx,
                    },
                )]),
            );
            bind_plane.data_channel_signal.notify_waiters();
        });
        let picked = tokio::time::timeout(
            StdDuration::from_secs(2),
            wait_for_data_channel(&plane, device),
        )
        .await
        .expect("wait should return once a channel binds");
        assert_eq!(picked, Some(1));
        bind.await.unwrap();
    }

    #[tokio::test]
    async fn wait_for_data_channel_aborts_when_session_vanishes() {
        let plane = DataPlane::default();
        let device = Uuid::new_v4();
        let (session_tx, _session_rx) = mpsc::channel::<Message>(8);
        plane.sessions.write().await.insert(
            device,
            SessionEntry {
                connection_id: Uuid::new_v4(),
                tx: session_tx,
            },
        );
        let drop_plane = plane.clone();
        let drop = tokio::spawn(async move {
            tokio::time::sleep(StdDuration::from_millis(100)).await;
            drop_plane.sessions.write().await.remove(&device);
            drop_plane.session_signal.notify_waiters();
        });
        let started = Instant::now();
        let result = tokio::time::timeout(
            StdDuration::from_secs(2),
            wait_for_data_channel(&plane, device),
        )
        .await
        .expect("wait should abort when the control session disappears");
        assert_eq!(result, None);
        assert!(started.elapsed() < StdDuration::from_secs(1));
        drop.await.unwrap();
    }

    #[tokio::test]
    async fn wait_for_data_channel_times_out_without_channel() {
        let plane = DataPlane::default();
        let device = Uuid::new_v4();
        let (session_tx, _session_rx) = mpsc::channel::<Message>(8);
        plane.sessions.write().await.insert(
            device,
            SessionEntry {
                connection_id: Uuid::new_v4(),
                tx: session_tx,
            },
        );
        let started = Instant::now();
        let result =
            wait_for_data_channel_with_timeout(&plane, device, StdDuration::from_millis(50)).await;
        assert_eq!(result, None);
        assert!(started.elapsed() >= StdDuration::from_millis(40));
    }

    #[tokio::test]
    async fn pick_data_channel_ignores_stale_channels() {
        let plane = DataPlane::default();
        let device = Uuid::new_v4();
        let current = Uuid::new_v4();
        let stale = Uuid::new_v4();
        let (session_tx, _session_rx) = mpsc::channel::<Message>(8);
        plane.sessions.write().await.insert(
            device,
            SessionEntry {
                connection_id: current,
                tx: session_tx,
            },
        );
        let (channel_tx, _channel_rx) = mpsc::channel::<Message>(8);
        plane.data_channels.write().await.insert(
            device,
            HashMap::from([
                (
                    1,
                    DataChannel {
                        connection_id: stale,
                        tx: channel_tx.clone(),
                    },
                ),
                (
                    2,
                    DataChannel {
                        connection_id: current,
                        tx: channel_tx,
                    },
                ),
            ]),
        );
        assert_eq!(pick_data_channel(&plane, device).await, Some(2));
    }

    #[tokio::test]
    async fn send_control_to_session_reports_full_queue_without_waiting() {
        let (tx, _rx) = mpsc::channel::<Message>(1);
        let send_tx = tx.clone();
        let session = SessionEntry {
            connection_id: Uuid::new_v4(),
            tx,
        };
        let message = ControlMessage::Heartbeat {
            version: PROTOCOL_VERSION,
            latency_ms: 0,
        };
        let _ = send_tx.try_send(Message::Text(String::from("first").into()));
        let started = Instant::now();
        assert!(
            !send_control_to_session(&session, &message, None).await,
            "full queue must report control unavailable"
        );
        assert!(
            started.elapsed() < StdDuration::from_millis(50),
            "non-blocking send must not wait for queue space"
        );
    }

    #[tokio::test]
    async fn send_control_to_session_waits_until_queue_drains() {
        let (tx, mut rx) = mpsc::channel::<Message>(1);
        let session = SessionEntry {
            connection_id: Uuid::new_v4(),
            tx: tx.clone(),
        };
        let message = ControlMessage::Heartbeat {
            version: PROTOCOL_VERSION,
            latency_ms: 0,
        };
        let _ = tx.try_send(Message::Text(String::from("first").into()));
        let drain = tokio::spawn(async move {
            tokio::time::sleep(StdDuration::from_millis(100)).await;
            let _ = rx.recv().await;
            // Keep the receiver alive so the pending send completes instead
            // of seeing a closed channel when this task would otherwise end.
            tokio::time::sleep(StdDuration::from_millis(200)).await;
        });
        let started = Instant::now();
        assert!(
            send_control_to_session(&session, &message, Some(StdDuration::from_secs(2))).await,
            "timed send must succeed once the queue drains"
        );
        assert!(started.elapsed() >= StdDuration::from_millis(80));
        drain.await.unwrap();
    }

    #[tokio::test]
    async fn send_control_to_session_times_out_when_queue_stays_full() {
        let (tx, _rx) = mpsc::channel::<Message>(1);
        let send_tx = tx.clone();
        let session = SessionEntry {
            connection_id: Uuid::new_v4(),
            tx,
        };
        let message = ControlMessage::Heartbeat {
            version: PROTOCOL_VERSION,
            latency_ms: 0,
        };
        let _ = send_tx.try_send(Message::Text(String::from("first").into()));
        let started = Instant::now();
        assert!(
            !send_control_to_session(&session, &message, Some(StdDuration::from_millis(50))).await,
            "timed send must fail once the deadline passes"
        );
        assert!(started.elapsed() >= StdDuration::from_millis(40));
        assert!(started.elapsed() < StdDuration::from_secs(1));
    }

    #[tokio::test]
    async fn routes_tcp_and_udp_concurrently_without_hanging() {
        let plane = DataPlane::default();
        let device = Uuid::new_v4();
        let tcp_id: u128 = 1;
        let udp_id: u128 = 2;
        let (tcp_tx, mut tcp_rx) = mpsc::channel::<Vec<u8>>(4096);
        assert!(try_register_stream(&plane, tcp_id, device, Uuid::new_v4(), 1, tcp_tx, 100).await);
        let (udp_tx, mut udp_rx) = mpsc::channel::<Vec<u8>>(4096);
        insert_udp_session(
            &plane,
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
        )
        .await;
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
            assert!(try_register_stream(&plane, id, device, Uuid::new_v4(), channel, tx, 8).await);
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
        insert_udp_session(
            &plane,
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
        )
        .await;
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

    #[tokio::test]
    async fn tcp_queue_full_waits_instead_of_closing_stream() {
        let plane = DataPlane::default();
        let tcp_id: u128 = 77;
        let (tx, mut rx) = mpsc::channel::<Vec<u8>>(1);
        plane.streams.write().await.insert(
            tcp_id,
            StreamEntry {
                device_id: Uuid::new_v4(),
                tunnel_id: Uuid::new_v4(),
                data_channel: 1,
                tx,
                slot: Arc::new(Mutex::new(StreamSlot::default())),
            },
        );
        assert_eq!(
            route_stream_data(&plane, tcp_id, b"first").await,
            RouteOutcome::Ok
        );
        // The queue is now full; routing must wait (backpressure) instead of
        // dropping the frame or removing the stream entry.
        let routing_plane = plane.clone();
        let routing =
            tokio::spawn(async move { route_stream_data(&routing_plane, tcp_id, b"second").await });
        tokio::time::sleep(StdDuration::from_millis(100)).await;
        assert!(
            plane.streams.read().await.contains_key(&tcp_id),
            "saturated TCP stream must stay registered while backpressure applies"
        );
        // Draining the queue lets the waiting frame through, still in order.
        assert_eq!(rx.recv().await.as_deref(), Some(b"first".as_slice()));
        assert_eq!(routing.await.unwrap(), RouteOutcome::Ok);
        assert_eq!(rx.recv().await.as_deref(), Some(b"second".as_slice()));
        assert!(plane.streams.read().await.contains_key(&tcp_id));
    }

    #[tokio::test]
    async fn tcp_queue_full_times_out_and_closes_stream() {
        let plane = DataPlane::default();
        let tcp_id: u128 = 78;
        let (tx, _rx) = mpsc::channel::<Vec<u8>>(1);
        plane.streams.write().await.insert(
            tcp_id,
            StreamEntry {
                device_id: Uuid::new_v4(),
                tunnel_id: Uuid::new_v4(),
                data_channel: 1,
                tx,
                slot: Arc::new(Mutex::new(StreamSlot::default())),
            },
        );
        assert_eq!(
            route_stream_data(&plane, tcp_id, b"first").await,
            RouteOutcome::Ok
        );
        // A full queue that never drains must hit the bounded timeout instead
        // of hanging the caller; only then is the stream closed.
        let outcome = tokio::time::timeout(
            StdDuration::from_secs(2),
            route_stream_data_with_timeout(&plane, tcp_id, b"second", StdDuration::from_millis(50)),
        )
        .await
        .expect("routing must return after its bounded timeout");
        assert_eq!(outcome, RouteOutcome::StreamSendTimeout(tcp_id));
        assert!(!plane.streams.read().await.contains_key(&tcp_id));
    }

    #[tokio::test]
    async fn tcp_stream_channel_closed_removes_entry() {
        let plane = DataPlane::default();
        let tcp_id: u128 = 79;
        let (tx, rx) = mpsc::channel::<Vec<u8>>(1);
        drop(rx);
        plane.streams.write().await.insert(
            tcp_id,
            StreamEntry {
                device_id: Uuid::new_v4(),
                tunnel_id: Uuid::new_v4(),
                data_channel: 1,
                tx,
                slot: Arc::new(Mutex::new(StreamSlot::default())),
            },
        );
        assert_eq!(
            route_stream_data(&plane, tcp_id, b"data").await,
            RouteOutcome::StreamChannelClosed(tcp_id)
        );
        assert!(!plane.streams.read().await.contains_key(&tcp_id));
    }

    #[tokio::test]
    async fn tunnel_max_connections_limits_concurrent_tcp_streams() {
        let plane = DataPlane::default();
        let device = Uuid::new_v4();
        let tunnel_a = Uuid::new_v4();
        let tunnel_b = Uuid::new_v4();
        let (tx, _rx) = mpsc::channel::<Vec<u8>>(8);
        assert!(try_register_stream(&plane, 1, device, tunnel_a, 1, tx.clone(), 2).await);
        assert!(try_register_stream(&plane, 2, device, tunnel_a, 1, tx.clone(), 2).await);
        // Tunnel A is at its limit; the next TCP connection must be rejected
        // without registering a stream.
        assert!(!try_register_stream(&plane, 3, device, tunnel_a, 1, tx.clone(), 2).await);
        assert!(!plane.streams.read().await.contains_key(&3));
        // Other tunnels or devices are not affected by tunnel A's limit.
        assert!(try_register_stream(&plane, 4, device, tunnel_b, 1, tx.clone(), 2).await);
        assert!(try_register_stream(&plane, 5, Uuid::new_v4(), tunnel_a, 1, tx.clone(), 2).await);
        // Closing one connection frees a slot for the same tunnel.
        remove_stream_entry(&plane, 1).await;
        assert!(try_register_stream(&plane, 6, device, tunnel_a, 1, tx.clone(), 2).await);
    }

    #[tokio::test]
    async fn stream_slot_quota_blocks_only_that_stream() {
        let plane = DataPlane::default();
        let device = Uuid::new_v4();
        let (tx, _rx) = mpsc::channel::<Vec<u8>>(8);
        let id_a: u128 = 101;
        let id_b: u128 = 102;
        let slot_a = Arc::new(Mutex::new(StreamSlot::default()));
        let slot_b = Arc::new(Mutex::new(StreamSlot::default()));
        plane.streams.write().await.insert(
            id_a,
            StreamEntry {
                device_id: device,
                tunnel_id: Uuid::new_v4(),
                data_channel: 1,
                tx: tx.clone(),
                slot: slot_a.clone(),
            },
        );
        plane.streams.write().await.insert(
            id_b,
            StreamEntry {
                device_id: device,
                tunnel_id: Uuid::new_v4(),
                data_channel: 1,
                tx,
                slot: slot_b.clone(),
            },
        );
        for _ in 0..STREAM_CHANNEL_QUOTA {
            assert!(acquire_stream_slot(&plane, &slot_a, id_a).await);
        }
        // Stream A is at quota; its next slot must wait...
        let blocked = tokio::spawn({
            let plane = plane.clone();
            let slot = slot_a.clone();
            async move {
                tokio::time::timeout(
                    StdDuration::from_millis(100),
                    acquire_stream_slot(&plane, &slot, id_a),
                )
                .await
            }
        });
        // ...while stream B can still reserve a slot immediately.
        assert!(acquire_stream_slot(&plane, &slot_b, id_b).await);
        assert!(
            blocked.await.unwrap().is_err(),
            "stream A must stay blocked at quota"
        );
        // Releasing one forwarded frame unblocks A.
        release_stream_slot(&plane, id_a).await;
        let acquired = tokio::time::timeout(
            StdDuration::from_secs(1),
            acquire_stream_slot(&plane, &slot_a, id_a),
        )
        .await
        .expect("released quota must unblock the stream");
        assert!(acquired);
    }

    #[tokio::test]
    async fn stream_slot_quota_aborts_when_stream_removed() {
        let plane = DataPlane::default();
        let device = Uuid::new_v4();
        let id: u128 = 103;
        let (tx, _rx) = mpsc::channel::<Vec<u8>>(8);
        let slot = Arc::new(Mutex::new(StreamSlot::default()));
        plane.streams.write().await.insert(
            id,
            StreamEntry {
                device_id: device,
                tunnel_id: Uuid::new_v4(),
                data_channel: 1,
                tx,
                slot: slot.clone(),
            },
        );
        for _ in 0..STREAM_CHANNEL_QUOTA {
            assert!(acquire_stream_slot(&plane, &slot, id).await);
        }
        let blocked = tokio::spawn({
            let plane = plane.clone();
            let slot = slot.clone();
            async move {
                tokio::time::timeout(
                    StdDuration::from_millis(100),
                    acquire_stream_slot(&plane, &slot, id),
                )
                .await
            }
        });
        // Removing the stream wakes the waiting bridge and reports failure.
        remove_stream_entry(&plane, id).await;
        let result = tokio::time::timeout(StdDuration::from_secs(1), blocked)
            .await
            .expect("blocked task must finish after stream removal")
            .expect("acquire must return after stream removal");
        assert_eq!(result, Ok(false));
    }

    #[tokio::test]
    async fn pick_data_channel_prefers_lowest_load() {
        let plane = DataPlane::default();
        let device = Uuid::new_v4();
        let connection = Uuid::new_v4();
        let (session_tx, _session_rx) = mpsc::channel::<Message>(8);
        plane.sessions.write().await.insert(
            device,
            SessionEntry {
                connection_id: connection,
                tx: session_tx,
            },
        );
        let (channel_tx, _channel_rx) = mpsc::channel::<Message>(8);
        plane.data_channels.write().await.insert(
            device,
            HashMap::from([
                (
                    1,
                    DataChannel {
                        connection_id: connection,
                        tx: channel_tx.clone(),
                    },
                ),
                (
                    2,
                    DataChannel {
                        connection_id: connection,
                        tx: channel_tx,
                    },
                ),
            ]),
        );
        let (stream_tx, _stream_rx) = mpsc::channel::<Vec<u8>>(8);
        assert!(try_register_stream(&plane, 10, device, Uuid::new_v4(), 2, stream_tx, 10).await);
        assert_eq!(pick_data_channel(&plane, device).await, Some(1));
    }

    #[tokio::test]
    async fn channel_load_counters_track_concurrent_stream_registration() {
        let plane = DataPlane::default();
        let device = Uuid::new_v4();
        let tunnel = Uuid::new_v4();
        let (tx, _rx) = mpsc::channel::<Vec<u8>>(8);
        let mut tasks = Vec::new();
        for id in 0..50_u128 {
            let plane = plane.clone();
            let tx = tx.clone();
            tasks.push(tokio::spawn(async move {
                assert!(
                    try_register_stream(&plane, id, device, tunnel, 1, tx, 100).await,
                    "concurrent registration must not exceed the configured limit"
                );
            }));
        }
        for task in tasks {
            task.await.unwrap();
        }
        assert_eq!(plane.channel_load(device, 1), 50);
        // Removing streams on the direct path must decrement the counter too.
        for id in 0..20_u128 {
            remove_stream_entry(&plane, id).await;
        }
        assert_eq!(plane.channel_load(device, 1), 30);
        // close_channel_streams covers the bulk teardown path.
        let removed = close_channel_streams(&plane, device, 1).await;
        assert_eq!(removed.len(), 30);
        assert_eq!(plane.channel_load(device, 1), 0);
    }

    #[tokio::test]
    async fn udp_peer_index_matches_sessions_and_cleans_up() {
        let plane = DataPlane::default();
        let device = Uuid::new_v4();
        let tunnel = Uuid::new_v4();
        let peer_a: SocketAddr = "127.0.0.1:1000".parse().unwrap();
        let peer_b: SocketAddr = "127.0.0.1:2000".parse().unwrap();
        let peer_c: SocketAddr = "10.0.0.1:3000".parse().unwrap();
        for (id, peer) in [(1_u128, peer_a), (2, peer_b), (3, peer_c)] {
            let (outbox, _rx) = mpsc::channel::<Vec<u8>>(8);
            insert_udp_session(
                &plane,
                id,
                UdpSession {
                    device_id: device,
                    connection_id: Uuid::new_v4(),
                    tunnel_id: tunnel,
                    data_channel: 1,
                    peer,
                    outbox,
                    last_seen: Instant::now(),
                },
            )
            .await;
        }
        let index = plane.udp_peers.read().await;
        assert_eq!(
            index.get(&tunnel).and_then(|peers| peers.get(&peer_a)),
            Some(&1)
        );
        assert_eq!(
            index.get(&tunnel).and_then(|peers| peers.get(&peer_b)),
            Some(&2)
        );
        assert_eq!(
            index.get(&tunnel).and_then(|peers| peers.get(&peer_c)),
            Some(&3)
        );
        drop(index);
        assert_eq!(plane.channel_load(device, 1), 3);
        // Removing one session drops its peer entry and the counter.
        remove_udp_session(&plane, 2).await;
        assert_eq!(plane.channel_load(device, 1), 2);
        let index = plane.udp_peers.read().await;
        assert_eq!(
            index.get(&tunnel).and_then(|peers| peers.get(&peer_b)),
            None
        );
        assert_eq!(
            index.get(&tunnel).and_then(|peers| peers.get(&peer_a)),
            Some(&1)
        );
        drop(index);
        // Removing the last sessions drops the empty per-tunnel map.
        remove_udp_session(&plane, 1).await;
        remove_udp_session(&plane, 3).await;
        assert!(plane.udp_peers.read().await.get(&tunnel).is_none());
        assert_eq!(plane.channel_load(device, 1), 0);
    }

    #[test]
    fn agent_defaults_validation_rejects_out_of_range_values() {
        let ok = AgentDefaults {
            data_channels: 4,
            ..AgentDefaults::default()
        };
        assert!(ok.validate(16).is_ok());
        let too_many = AgentDefaults {
            data_channels: 9,
            ..AgentDefaults::default()
        };
        assert!(too_many.validate(16).is_err());
        let above_cap = AgentDefaults {
            data_channels: 6,
            ..AgentDefaults::default()
        };
        assert!(above_cap.validate(4).is_err());
        let inverted_reconnect = AgentDefaults {
            reconnect_min_secs: 30,
            reconnect_max_secs: 10,
            ..AgentDefaults::default()
        };
        assert!(inverted_reconnect.validate(16).is_err());
        let bad_level = AgentDefaults {
            log_level: "verbose".into(),
            ..AgentDefaults::default()
        };
        assert!(bad_level.validate(16).is_err());
    }

    #[test]
    fn device_overrides_validation_checks_present_fields_only() {
        let overrides = DeviceOverrides {
            data_channels: Some(3),
            ..DeviceOverrides::default()
        };
        assert!(overrides.validate(16).is_ok());
        let bad = DeviceOverrides {
            pong_timeout_secs: Some(1),
            ..DeviceOverrides::default()
        };
        assert!(bad.validate(16).is_err());
    }

    #[test]
    fn constant_time_eq_matches_and_rejects() {
        assert!(constant_time_eq("abc123", "abc123"));
        assert!(!constant_time_eq("abc123", "abc124"));
        assert!(!constant_time_eq("abc123", "abc12"));
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
/// Global agent defaults. Every field is optional server-wide: stored values
/// fall back to the constants below, and per-device overrides layer on top.
#[derive(Serialize, Deserialize, Clone, PartialEq)]
struct AgentDefaults {
    server_url: String,
    data_channels: u16,
    heartbeat_secs: u64,
    pong_timeout_secs: u64,
    reconnect_min_secs: u64,
    reconnect_max_secs: u64,
    log_level: String,
}

impl Default for AgentDefaults {
    fn default() -> Self {
        Self {
            server_url: String::new(),
            data_channels: 2,
            heartbeat_secs: 10,
            pong_timeout_secs: 25,
            reconnect_min_secs: 1,
            reconnect_max_secs: 10,
            log_level: "info".into(),
        }
    }
}

impl AgentDefaults {
    /// Validates ranges and shape. `max_channels` is the server's own
    /// DATA_CHANNELS_MAX cap so the agent never opens more than the server
    /// will accept.
    fn validate(&self, max_channels: u16) -> Result<(), String> {
        if !(1..=8).contains(&self.data_channels) {
            return Err("data_channels must be between 1 and 8".into());
        }
        if self.data_channels > max_channels {
            return Err(format!(
                "data_channels must not exceed the server cap {max_channels}"
            ));
        }
        if !(3..=60).contains(&self.heartbeat_secs) {
            return Err("heartbeat_secs must be between 3 and 60".into());
        }
        if !(5..=300).contains(&self.pong_timeout_secs) {
            return Err("pong_timeout_secs must be between 5 and 300".into());
        }
        if !(1..=60).contains(&self.reconnect_min_secs) {
            return Err("reconnect_min_secs must be between 1 and 60".into());
        }
        if !(1..=300).contains(&self.reconnect_max_secs) {
            return Err("reconnect_max_secs must be between 1 and 300".into());
        }
        if self.reconnect_max_secs < self.reconnect_min_secs {
            return Err("reconnect_max_secs must be >= reconnect_min_secs".into());
        }
        if !matches!(
            self.log_level.as_str(),
            "error" | "warn" | "info" | "debug" | "trace"
        ) {
            return Err("log_level must be one of error/warn/info/debug/trace".into());
        }
        if !self.server_url.is_empty()
            && !(self.server_url.starts_with("ws://") || self.server_url.starts_with("wss://"))
        {
            return Err("server_url must start with ws:// or wss://".into());
        }
        Ok(())
    }

    fn to_agent_settings(&self, device_name: String) -> AgentSettings {
        AgentSettings {
            device_name,
            server_url: self.server_url.clone(),
            data_channels: self.data_channels,
            heartbeat_secs: self.heartbeat_secs,
            pong_timeout_secs: self.pong_timeout_secs,
            reconnect_min_secs: self.reconnect_min_secs,
            reconnect_max_secs: self.reconnect_max_secs,
            log_level: self.log_level.clone(),
        }
    }
}

/// Per-device overrides; NULL means "inherit the global default".
#[derive(Serialize, Deserialize, Default, Clone)]
struct DeviceOverrides {
    server_url: Option<String>,
    data_channels: Option<u16>,
    heartbeat_secs: Option<u64>,
    pong_timeout_secs: Option<u64>,
    reconnect_min_secs: Option<u64>,
    reconnect_max_secs: Option<u64>,
    log_level: Option<String>,
}

impl DeviceOverrides {
    fn validate(&self, max_channels: u16) -> Result<(), String> {
        AgentDefaults {
            server_url: self.server_url.clone().unwrap_or_default(),
            data_channels: self.data_channels.unwrap_or(2),
            heartbeat_secs: self.heartbeat_secs.unwrap_or(10),
            pong_timeout_secs: self.pong_timeout_secs.unwrap_or(25),
            reconnect_min_secs: self.reconnect_min_secs.unwrap_or(1),
            reconnect_max_secs: self.reconnect_max_secs.unwrap_or(10),
            log_level: self.log_level.clone().unwrap_or_else(|| "info".into()),
        }
        .validate(max_channels)
    }
}

#[derive(Serialize)]
struct DeviceSettingsView {
    device_name: String,
    /// Effective settings after merging global defaults with overrides.
    settings: AgentSettings,
    overrides: DeviceOverrides,
}

#[derive(Deserialize)]
struct UpdateDeviceSettings {
    device_name: Option<String>,
    /// Full replacement of this device's overrides; null fields inherit the
    /// global default.
    overrides: DeviceOverrides,
}

#[derive(Serialize, Deserialize)]
struct Settings {
    bandwidth_limit_mbps: u64,
    agent_defaults: AgentDefaults,
}

#[derive(Serialize, FromRow)]
struct EnrollmentRow {
    id: Uuid,
    device_name: String,
    status: String,
    created_at: chrono::DateTime<Utc>,
    expires_at: chrono::DateTime<Utc>,
}

#[derive(Deserialize)]
struct ApproveEnrollment {
    code: String,
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
        redis_conn: Arc::new(Mutex::new(None)),
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
        pending_enrollments: Arc::new(RwLock::new(HashMap::new())),
    };
    tokio::spawn(heartbeat_flusher_loop(state.clone()));
    tokio::spawn(reconcile_listeners(state.clone()));
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
        .route("/api/v1/devices/{id}", delete(delete_device))
        .route(
            "/api/v1/devices/{id}/settings",
            get(get_device_settings).put(update_device_settings),
        )
        .route(
            "/api/v1/devices/{id}/rotate-token",
            post(rotate_device_token),
        )
        .route("/api/v1/enrollments", get(list_enrollments))
        .route("/api/v1/enrollments/{id}/approve", post(approve_enrollment))
        .route("/api/v1/enrollments/{id}/deny", post(deny_enrollment))
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
        remove_stream_entry(&state.plane, id).await;
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
            remove_udp_session(&state.plane, id).await;
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
        agent_defaults: load_agent_defaults(&state.db).await.unwrap_or_default(),
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
    input
        .agent_defaults
        .validate(state.data_channels_max)
        .map_err(|message| (StatusCode::UNPROCESSABLE_ENTITY, message))?;
    set_setting(
        &state.db,
        "bandwidth_limit_mbps",
        &input.bandwidth_limit_mbps.to_string(),
    )
    .await
    .map_err(|_| {
        (
            StatusCode::INTERNAL_SERVER_ERROR,
            "Could not save settings".into(),
        )
    })?;
    save_agent_defaults(&state.db, &input.agent_defaults)
        .await
        .map_err(|_| {
            (
                StatusCode::INTERNAL_SERVER_ERROR,
                "Could not save agent defaults".into(),
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
    // Recompute and push the effective settings of every online device so
    // global default changes propagate immediately.
    for device_id in state
        .plane
        .sessions
        .read()
        .await
        .keys()
        .copied()
        .collect::<Vec<_>>()
    {
        send_effective_settings(&state, device_id).await;
    }
    audit(
        &state.db,
        Some(actor.id),
        "settings.bandwidth_updated",
        &input.bandwidth_limit_mbps.to_string(),
    )
    .await;
    audit(
        &state.db,
        Some(actor.id),
        "settings.agent_defaults_updated",
        "agent defaults",
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

/// Deletes a device and everything it owns: tunnels, access tokens, per-device
/// settings, and enrollment records. Public listeners are stopped and the
/// live control session is torn down so the device drops immediately; its
/// (now deleted) token will be rejected on reconnect and it must re-enroll.
async fn delete_device(
    State(state): State<AppState>,
    headers: HeaderMap,
    Path(id): Path<Uuid>,
) -> Result<Json<serde_json::Value>, (StatusCode, String)> {
    let actor = admin(&headers, &state)
        .await
        .map_err(|s| (s, "Unauthorized".into()))?;
    let device_name: Option<String> = sqlx::query_scalar("SELECT name FROM devices WHERE id=$1")
        .bind(id)
        .fetch_optional(&state.db)
        .await
        .map_err(|_| (StatusCode::INTERNAL_SERVER_ERROR, "Query failed".into()))?;
    let Some(device_name) = device_name else {
        return Err((StatusCode::NOT_FOUND, "Device not found".into()));
    };
    // Stop every public listener owned by the device (this also drops its UDP
    // sessions), then tear down the live control/data channels.
    let tunnel_ids: Vec<Uuid> = sqlx::query_scalar("SELECT id FROM tunnels WHERE device_id=$1")
        .bind(id)
        .fetch_all(&state.db)
        .await
        .unwrap_or_default();
    for tunnel_id in tunnel_ids {
        remove_listener(&state, tunnel_id).await;
    }
    let session = {
        let sessions = state.plane.sessions.read().await;
        sessions.get(&id).cloned()
    };
    if let Some(session) = session {
        teardown_device_data_channels(&state, id, session.connection_id).await;
        drop_invalid_udp_sessions(&state, id, session.connection_id).await;
        let mut sessions = state.plane.sessions.write().await;
        let removed = remove_session_if_owned(&mut sessions, id, session.connection_id);
        if removed {
            state.plane.session_signal.notify_waiters();
        }
    }
    let mut tx = state.db.begin().await.map_err(|_| {
        (
            StatusCode::INTERNAL_SERVER_ERROR,
            "Could not begin transaction".into(),
        )
    })?;
    // enrollments reference devices without ON DELETE CASCADE; clear them
    // first, then the devices row cascades to tunnels/access_tokens/device_settings.
    sqlx::query("DELETE FROM enrollments WHERE device_id=$1")
        .bind(id)
        .execute(&mut *tx)
        .await
        .map_err(|_| {
            (
                StatusCode::INTERNAL_SERVER_ERROR,
                "Could not delete device records".into(),
            )
        })?;
    let result = sqlx::query("DELETE FROM devices WHERE id=$1")
        .bind(id)
        .execute(&mut *tx)
        .await
        .map_err(|_| {
            (
                StatusCode::INTERNAL_SERVER_ERROR,
                "Could not delete device".into(),
            )
        })?;
    if result.rows_affected() == 0 {
        let _ = tx.rollback().await;
        return Err((StatusCode::NOT_FOUND, "Device not found".into()));
    }
    tx.commit().await.map_err(|_| {
        (
            StatusCode::INTERNAL_SERVER_ERROR,
            "Could not commit deletion".into(),
        )
    })?;
    audit(&state.db, Some(actor.id), "device.deleted", &device_name).await;
    tracing::info!(%id, "device deleted");
    Ok(Json(serde_json::json!({"deleted": true})))
}
async fn list_tunnels(
    State(state): State<AppState>,
    headers: HeaderMap,
) -> Result<Json<Vec<TunnelRecord>>, StatusCode> {
    admin(&headers, &state).await?;
    let mut rows = sqlx::query_as::<_, TunnelRecord>("SELECT t.id,t.name,t.kind,t.public_port,t.local_host,t.local_port,t.enabled,t.max_connections,t.device_id,CASE WHEN d.status='online' THEN 'ready' ELSE 'offline' END status,0::bigint connections FROM tunnels t JOIN devices d ON d.id=t.device_id ORDER BY t.public_port").fetch_all(&state.db).await.map_err(|_| StatusCode::INTERNAL_SERVER_ERROR)?;
    // Report real live usage instead of the placeholder zero: TCP/HTTP streams
    // plus UDP sessions currently active for each tunnel.
    let streams = state.plane.streams.read().await;
    let udp = state.plane.udp_sessions.read().await;
    for row in &mut rows {
        row.connections = (streams
            .values()
            .filter(|entry| entry.device_id == row.device_id && entry.tunnel_id == row.id)
            .count()
            + udp
                .values()
                .filter(|session| session.tunnel_id == row.id)
                .count()) as i64;
    }
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

fn constant_time_eq(a: &str, b: &str) -> bool {
    let a = a.as_bytes();
    let b = b.as_bytes();
    if a.len() != b.len() {
        return false;
    }
    a.iter().zip(b).fold(0u8, |acc, (x, y)| acc | (x ^ y)) == 0
}

async fn list_enrollments(
    State(state): State<AppState>,
    headers: HeaderMap,
) -> Result<Json<Vec<EnrollmentRow>>, StatusCode> {
    admin(&headers, &state).await?;
    let rows = sqlx::query_as::<_, EnrollmentRow>(
        "SELECT id, device_name, status, created_at, expires_at FROM enrollments \
         WHERE status = 'pending' AND expires_at > now() ORDER BY created_at DESC",
    )
    .fetch_all(&state.db)
    .await
    .map_err(|_| StatusCode::INTERNAL_SERVER_ERROR)?;
    Ok(Json(rows))
}

async fn approve_enrollment(
    State(state): State<AppState>,
    headers: HeaderMap,
    Path(id): Path<Uuid>,
    Json(input): Json<ApproveEnrollment>,
) -> Result<Json<serde_json::Value>, (StatusCode, String)> {
    let actor = admin(&headers, &state)
        .await
        .map_err(|s| (s, "Unauthorized".into()))?;
    let code = input.code.trim().to_uppercase();
    if code.len() != ENROLL_CODE_LEN
        || !code
            .bytes()
            .all(|byte| ENROLL_CODE_ALPHABET.contains(&byte))
    {
        return Err((
            StatusCode::UNPROCESSABLE_ENTITY,
            "Enrollment code must be 8 characters from the pairing alphabet".into(),
        ));
    }
    let row: Option<(String, String, chrono::DateTime<Utc>)> = sqlx::query_as(
        "SELECT code_hash, device_name, expires_at FROM enrollments \
         WHERE id = $1 AND status = 'pending'",
    )
    .bind(id)
    .fetch_optional(&state.db)
    .await
    .map_err(|_| (StatusCode::INTERNAL_SERVER_ERROR, "Query failed".into()))?;
    let Some((code_hash, device_name, expires_at)) = row else {
        return Err((
            StatusCode::NOT_FOUND,
            "Enrollment not found or already resolved".into(),
        ));
    };
    if expires_at <= Utc::now() {
        let _ = sqlx::query("UPDATE enrollments SET status='expired' WHERE id=$1")
            .bind(id)
            .execute(&state.db)
            .await;
        return Err((StatusCode::GONE, "Enrollment code expired".into()));
    }
    if !constant_time_eq(&code_hash, &hash_token(&code)) {
        return Err((
            StatusCode::UNPROCESSABLE_ENTITY,
            "Enrollment code does not match".into(),
        ));
    }
    let Some(entry) = state.pending_enrollments.write().await.remove(&id) else {
        return Err((
            StatusCode::CONFLICT,
            "Enrollment connection is no longer online".into(),
        ));
    };
    if entry.code_hash != code_hash || entry.expires_at <= Utc::now() {
        return Err((StatusCode::GONE, "Enrollment expired".into()));
    }
    let (device_id, token) = create_enrolled_device(&state.db, &device_name)
        .await
        .map_err(|_| {
            (
                StatusCode::INTERNAL_SERVER_ERROR,
                "Could not create device".into(),
            )
        })?;
    let _ = sqlx::query(
        "UPDATE enrollments SET status='approved', approved_by=$1, approved_at=now(), \
         device_id=$2 WHERE id=$3 AND status='pending'",
    )
    .bind(actor.id)
    .bind(device_id)
    .bind(id)
    .execute(&state.db)
    .await;
    let _ = entry
        .tx
        .send(EnrollmentDecision::Approved { token, device_id });
    audit(
        &state.db,
        Some(actor.id),
        "enrollment.approved",
        &device_name,
    )
    .await;
    Ok(Json(
        serde_json::json!({"approved": true, "device_id": device_id}),
    ))
}

async fn deny_enrollment(
    State(state): State<AppState>,
    headers: HeaderMap,
    Path(id): Path<Uuid>,
) -> Result<Json<serde_json::Value>, (StatusCode, String)> {
    let actor = admin(&headers, &state)
        .await
        .map_err(|s| (s, "Unauthorized".into()))?;
    let device_name: Option<String> =
        sqlx::query_scalar("SELECT device_name FROM enrollments WHERE id=$1 AND status='pending'")
            .bind(id)
            .fetch_optional(&state.db)
            .await
            .map_err(|_| (StatusCode::INTERNAL_SERVER_ERROR, "Query failed".into()))?;
    let Some(device_name) = device_name else {
        return Err((
            StatusCode::NOT_FOUND,
            "Enrollment not found or already resolved".into(),
        ));
    };
    let _ = sqlx::query("UPDATE enrollments SET status='denied' WHERE id=$1 AND status='pending'")
        .bind(id)
        .execute(&state.db)
        .await;
    if let Some(entry) = state.pending_enrollments.write().await.remove(&id) {
        let _ = entry.tx.send(EnrollmentDecision::Denied);
    }
    audit(&state.db, Some(actor.id), "enrollment.denied", &device_name).await;
    Ok(Json(serde_json::json!({"denied": true})))
}

async fn get_device_settings(
    State(state): State<AppState>,
    headers: HeaderMap,
    Path(id): Path<Uuid>,
) -> Result<Json<DeviceSettingsView>, (StatusCode, String)> {
    admin(&headers, &state)
        .await
        .map_err(|s| (s, "Unauthorized".into()))?;
    if !device_exists(&state.db, id).await {
        return Err((StatusCode::NOT_FOUND, "Device not found".into()));
    }
    let settings = load_effective_settings(&state.db, id)
        .await
        .ok_or_else(|| (StatusCode::INTERNAL_SERVER_ERROR, "Query failed".into()))?;
    let overrides = load_device_overrides(&state.db, id)
        .await
        .ok_or_else(|| (StatusCode::INTERNAL_SERVER_ERROR, "Query failed".into()))?;
    Ok(Json(DeviceSettingsView {
        device_name: settings.device_name.clone(),
        settings,
        overrides,
    }))
}

async fn update_device_settings(
    State(state): State<AppState>,
    headers: HeaderMap,
    Path(id): Path<Uuid>,
    Json(input): Json<UpdateDeviceSettings>,
) -> Result<Json<DeviceSettingsView>, (StatusCode, String)> {
    let actor = admin(&headers, &state)
        .await
        .map_err(|s| (s, "Unauthorized".into()))?;
    let current_name: Option<String> = sqlx::query_scalar("SELECT name FROM devices WHERE id=$1")
        .bind(id)
        .fetch_optional(&state.db)
        .await
        .map_err(|_| (StatusCode::INTERNAL_SERVER_ERROR, "Query failed".into()))?;
    let Some(mut effective_name) = current_name else {
        return Err((StatusCode::NOT_FOUND, "Device not found".into()));
    };
    if let Some(name) = input.device_name {
        let name = name.trim().to_string();
        if name.is_empty() || name.chars().count() > 100 {
            return Err((
                StatusCode::UNPROCESSABLE_ENTITY,
                "Device name must be between 1 and 100 characters".into(),
            ));
        }
        sqlx::query("UPDATE devices SET name=$1 WHERE id=$2")
            .bind(&name)
            .bind(id)
            .execute(&state.db)
            .await
            .map_err(|_| {
                (
                    StatusCode::INTERNAL_SERVER_ERROR,
                    "Could not rename device".into(),
                )
            })?;
        effective_name = name;
    }
    input
        .overrides
        .validate(state.data_channels_max)
        .map_err(|message| (StatusCode::UNPROCESSABLE_ENTITY, message))?;
    save_device_overrides(&state.db, id, &input.overrides)
        .await
        .map_err(|_| {
            (
                StatusCode::INTERNAL_SERVER_ERROR,
                "Could not save device settings".into(),
            )
        })?;
    send_effective_settings(&state, id).await;
    audit(
        &state.db,
        Some(actor.id),
        "device.settings_updated",
        &effective_name,
    )
    .await;
    let settings = load_effective_settings(&state.db, id)
        .await
        .ok_or_else(|| (StatusCode::INTERNAL_SERVER_ERROR, "Query failed".into()))?;
    let overrides = load_device_overrides(&state.db, id)
        .await
        .ok_or_else(|| (StatusCode::INTERNAL_SERVER_ERROR, "Query failed".into()))?;
    Ok(Json(DeviceSettingsView {
        device_name: settings.device_name.clone(),
        settings,
        overrides,
    }))
}

async fn rotate_device_token(
    State(state): State<AppState>,
    headers: HeaderMap,
    Path(id): Path<Uuid>,
) -> Result<Json<serde_json::Value>, (StatusCode, String)> {
    let actor = admin(&headers, &state)
        .await
        .map_err(|s| (s, "Unauthorized".into()))?;
    let device_name: Option<String> = sqlx::query_scalar("SELECT name FROM devices WHERE id=$1")
        .bind(id)
        .fetch_optional(&state.db)
        .await
        .map_err(|_| (StatusCode::INTERNAL_SERVER_ERROR, "Query failed".into()))?;
    let Some(device_name) = device_name else {
        return Err((StatusCode::NOT_FOUND, "Device not found".into()));
    };
    if !state.plane.sessions.read().await.contains_key(&id) {
        return Err((
            StatusCode::CONFLICT,
            "Device must be online to rotate its token".into(),
        ));
    }
    let token = new_device_token();
    let token_hash = hash_token(&token);
    let created = sqlx::query(
        "INSERT INTO access_tokens(id, device_id, label, token_hash) \
         VALUES($1,$2,'rotate',$3)",
    )
    .bind(Uuid::new_v4())
    .bind(id)
    .bind(&token_hash)
    .execute(&state.db)
    .await;
    if created.is_err() {
        return Err((
            StatusCode::INTERNAL_SERVER_ERROR,
            "Could not create replacement token".into(),
        ));
    }
    let pushed = send_control(
        &state,
        id,
        &ControlMessage::TokenRotate {
            token: token.clone(),
        },
    )
    .await;
    if !pushed {
        let _ = sqlx::query("DELETE FROM access_tokens WHERE token_hash=$1")
            .bind(&token_hash)
            .execute(&state.db)
            .await;
        return Err((
            StatusCode::CONFLICT,
            "Device went offline; token was not rotated".into(),
        ));
    }
    // Old tokens are now invalid; the fresh one remains active.
    let _ = sqlx::query(
        "UPDATE access_tokens SET revoked_at=now() WHERE device_id=$1 AND revoked_at IS NULL \
         AND token_hash <> $2",
    )
    .bind(id)
    .bind(&token_hash)
    .execute(&state.db)
    .await;
    audit(
        &state.db,
        Some(actor.id),
        "device.token_rotated",
        &device_name,
    )
    .await;
    Ok(Json(serde_json::json!({"rotated": true})))
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
fn hash_token(token: &str) -> String {
    format!("{:x}", sha2::Sha256::digest(token.as_bytes()))
}
fn new_device_token() -> String {
    let mut bytes = [0_u8; 32];
    rand_core::OsRng.fill_bytes(&mut bytes);
    bytes.iter().map(|byte| format!("{byte:02x}")).collect()
}
async fn set_setting(db: &PgPool, key: &str, value: &str) -> Result<(), sqlx::Error> {
    sqlx::query(
        "INSERT INTO settings(key, value) VALUES($1, $2) \
         ON CONFLICT(key) DO UPDATE SET value = EXCLUDED.value",
    )
    .bind(key)
    .bind(value)
    .execute(db)
    .await?;
    Ok(())
}
async fn load_agent_defaults(db: &PgPool) -> Option<AgentDefaults> {
    let rows: Vec<(String, String)> =
        sqlx::query_as("SELECT key, value FROM settings WHERE key LIKE 'agent.%'")
            .fetch_all(db)
            .await
            .ok()?;
    let map: HashMap<String, String> = rows.into_iter().collect();
    let defaults = AgentDefaults::default();
    Some(AgentDefaults {
        server_url: map
            .get("agent.server_url")
            .cloned()
            .unwrap_or(defaults.server_url),
        data_channels: map
            .get("agent.data_channels")
            .and_then(|v| v.parse().ok())
            .filter(|n| (1..=8).contains(n))
            .unwrap_or(defaults.data_channels),
        heartbeat_secs: map
            .get("agent.heartbeat_secs")
            .and_then(|v| v.parse().ok())
            .filter(|n| (3..=60).contains(n))
            .unwrap_or(defaults.heartbeat_secs),
        pong_timeout_secs: map
            .get("agent.pong_timeout_secs")
            .and_then(|v| v.parse().ok())
            .filter(|n| (5..=300).contains(n))
            .unwrap_or(defaults.pong_timeout_secs),
        reconnect_min_secs: map
            .get("agent.reconnect_min_secs")
            .and_then(|v| v.parse().ok())
            .filter(|n| (1..=60).contains(n))
            .unwrap_or(defaults.reconnect_min_secs),
        reconnect_max_secs: map
            .get("agent.reconnect_max_secs")
            .and_then(|v| v.parse().ok())
            .filter(|n| (1..=300).contains(n))
            .unwrap_or(defaults.reconnect_max_secs),
        log_level: map
            .get("agent.log_level")
            .filter(|v| matches!(v.as_str(), "error" | "warn" | "info" | "debug" | "trace"))
            .cloned()
            .unwrap_or(defaults.log_level),
    })
}
async fn save_agent_defaults(db: &PgPool, values: &AgentDefaults) -> Result<(), sqlx::Error> {
    set_setting(db, "agent.server_url", &values.server_url).await?;
    set_setting(db, "agent.data_channels", &values.data_channels.to_string()).await?;
    set_setting(
        db,
        "agent.heartbeat_secs",
        &values.heartbeat_secs.to_string(),
    )
    .await?;
    set_setting(
        db,
        "agent.pong_timeout_secs",
        &values.pong_timeout_secs.to_string(),
    )
    .await?;
    set_setting(
        db,
        "agent.reconnect_min_secs",
        &values.reconnect_min_secs.to_string(),
    )
    .await?;
    set_setting(
        db,
        "agent.reconnect_max_secs",
        &values.reconnect_max_secs.to_string(),
    )
    .await?;
    set_setting(db, "agent.log_level", &values.log_level).await?;
    Ok(())
}
async fn load_device_overrides(db: &PgPool, device_id: Uuid) -> Option<DeviceOverrides> {
    let row: Option<(
        Option<String>,
        Option<i16>,
        Option<i64>,
        Option<i64>,
        Option<i64>,
        Option<i64>,
        Option<String>,
    )> = sqlx::query_as(
        "SELECT server_url, data_channels, heartbeat_secs, pong_timeout_secs, \
             reconnect_min_secs, reconnect_max_secs, log_level \
             FROM device_settings WHERE device_id = $1",
    )
    .bind(device_id)
    .fetch_optional(db)
    .await
    .ok()
    .flatten();
    Some(match row {
        Some((server_url, data_channels, heartbeat, pong, min, max, log_level)) => {
            DeviceOverrides {
                server_url,
                data_channels: data_channels.map(|v| v as u16),
                heartbeat_secs: heartbeat.map(|v| v as u64),
                pong_timeout_secs: pong.map(|v| v as u64),
                reconnect_min_secs: min.map(|v| v as u64),
                reconnect_max_secs: max.map(|v| v as u64),
                log_level,
            }
        }
        None => DeviceOverrides::default(),
    })
}
async fn save_device_overrides(
    db: &PgPool,
    device_id: Uuid,
    overrides: &DeviceOverrides,
) -> Result<(), sqlx::Error> {
    sqlx::query(
        "INSERT INTO device_settings(device_id, server_url, data_channels, heartbeat_secs, \
         pong_timeout_secs, reconnect_min_secs, reconnect_max_secs, log_level, updated_at) \
         VALUES($1,$2,$3,$4,$5,$6,$7,$8,now()) \
         ON CONFLICT(device_id) DO UPDATE SET \
         server_url=EXCLUDED.server_url, data_channels=EXCLUDED.data_channels, \
         heartbeat_secs=EXCLUDED.heartbeat_secs, pong_timeout_secs=EXCLUDED.pong_timeout_secs, \
         reconnect_min_secs=EXCLUDED.reconnect_min_secs, \
         reconnect_max_secs=EXCLUDED.reconnect_max_secs, log_level=EXCLUDED.log_level, \
         updated_at=now()",
    )
    .bind(device_id)
    .bind(&overrides.server_url)
    .bind(overrides.data_channels.map(|v| v as i16))
    .bind(overrides.heartbeat_secs.map(|v| v as i64))
    .bind(overrides.pong_timeout_secs.map(|v| v as i64))
    .bind(overrides.reconnect_min_secs.map(|v| v as i64))
    .bind(overrides.reconnect_max_secs.map(|v| v as i64))
    .bind(&overrides.log_level)
    .execute(db)
    .await?;
    Ok(())
}
/// Merges global defaults with per-device overrides and the authoritative
/// device name. Returns None when the device does not exist.
async fn load_effective_settings(db: &PgPool, device_id: Uuid) -> Option<AgentSettings> {
    let defaults = load_agent_defaults(db).await?;
    let overrides = load_device_overrides(db, device_id).await?;
    let device_name: String = sqlx::query_scalar("SELECT name FROM devices WHERE id=$1")
        .bind(device_id)
        .fetch_optional(db)
        .await
        .ok()
        .flatten()?;
    Some(
        AgentDefaults {
            server_url: overrides.server_url.clone().unwrap_or(defaults.server_url),
            data_channels: overrides.data_channels.unwrap_or(defaults.data_channels),
            heartbeat_secs: overrides.heartbeat_secs.unwrap_or(defaults.heartbeat_secs),
            pong_timeout_secs: overrides
                .pong_timeout_secs
                .unwrap_or(defaults.pong_timeout_secs),
            reconnect_min_secs: overrides
                .reconnect_min_secs
                .unwrap_or(defaults.reconnect_min_secs),
            reconnect_max_secs: overrides
                .reconnect_max_secs
                .unwrap_or(defaults.reconnect_max_secs),
            log_level: overrides.log_level.clone().unwrap_or(defaults.log_level),
        }
        .to_agent_settings(device_name),
    )
}
/// Pushes the device's effective settings to its online control session.
async fn send_effective_settings(state: &AppState, device_id: Uuid) {
    if let Some(settings) = load_effective_settings(&state.db, device_id).await {
        send_control(state, device_id, &ControlMessage::SettingsSync { settings }).await;
    }
}
/// Creates the device and a fresh token inside one transaction for an
/// approved enrollment; returns (device_id, plaintext token).
async fn create_enrolled_device(
    db: &PgPool,
    device_name: &str,
) -> Result<(Uuid, String), sqlx::Error> {
    let workspace =
        sqlx::query_scalar::<_, Uuid>("SELECT id FROM workspaces ORDER BY created_at LIMIT 1")
            .fetch_one(db)
            .await?;
    let device_id = Uuid::new_v4();
    let token = new_device_token();
    let token_hash = hash_token(&token);
    let mut tx = db.begin().await?;
    sqlx::query("INSERT INTO devices(id, workspace_id, name) VALUES($1,$2,$3)")
        .bind(device_id)
        .bind(workspace)
        .bind(device_name)
        .execute(&mut *tx)
        .await?;
    sqlx::query(
        "INSERT INTO access_tokens(id, device_id, label, token_hash, last_used_at) \
         VALUES($1,$2,'enroll',$3,now())",
    )
    .bind(Uuid::new_v4())
    .bind(device_id)
    .bind(&token_hash)
    .execute(&mut *tx)
    .await?;
    tx.commit().await?;
    tracing::info!(%device_id, "enrollment approved, device created");
    Ok((device_id, token))
}
async fn device_exists(db: &PgPool, device_id: Uuid) -> bool {
    sqlx::query_scalar::<_, Uuid>("SELECT id FROM devices WHERE id=$1")
        .bind(device_id)
        .fetch_optional(db)
        .await
        .ok()
        .flatten()
        .is_some()
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

/// Periodically persists in-memory heartbeats to the database and refreshes
/// the Redis online markers. Runs entirely outside the control read loops:
/// database/Redis slowness or outages only degrade online-status display,
/// never message processing or the data plane. Redis uses one reused
/// connection; a failed connection is dropped and recreated on the next tick.
async fn heartbeat_flusher_loop(state: AppState) {
    let mut ticker = tokio::time::interval(StdDuration::from_secs(HEARTBEAT_FLUSH_SECS));
    ticker.tick().await; // skip the immediate first tick
    loop {
        ticker.tick().await;
        let now = Instant::now();
        let stale_after = StdDuration::from_secs(HEARTBEAT_STALE_SECS);
        let heartbeats: Vec<(Uuid, HeartbeatEntry)> = {
            let mut map = state.plane.heartbeats.write().await;
            map.retain(|_, entry| now.duration_since(entry.last_seen) <= stale_after);
            map.iter()
                .map(|(device_id, entry)| (*device_id, entry.clone()))
                .collect()
        };
        if heartbeats.is_empty() {
            continue;
        }
        for (device_id, entry) in &heartbeats {
            if let Err(error) = sqlx::query(
                "UPDATE devices SET latency_ms=$1,last_seen_at=now(),status='online' WHERE id=$2",
            )
            .bind(entry.latency_ms)
            .bind(device_id)
            .execute(&state.db)
            .await
            {
                tracing::warn!(
                    %error,
                    device_id = %device_id,
                    "heartbeat flush to database failed"
                );
            }
        }
        let mut guard = state.redis_conn.lock().await;
        if guard.is_none() {
            match state.redis.get_multiplexed_tokio_connection().await {
                Ok(conn) => *guard = Some(conn),
                Err(error) => {
                    tracing::warn!(%error, "could not open reused Redis connection");
                    continue;
                }
            }
        }
        if let Some(conn) = guard.as_mut() {
            let mut broken = false;
            for (device_id, _) in &heartbeats {
                let result: redis::RedisResult<()> =
                    conn.set_ex(format!("online:{device_id}"), "1", 60).await;
                if let Err(error) = result {
                    tracing::warn!(
                        %error,
                        device_id = %device_id,
                        "redis online marker refresh failed"
                    );
                    broken = true;
                    break;
                }
            }
            if broken {
                *guard = None;
            }
        }
    }
}

async fn control_loop(socket: WebSocket, state: AppState) {
    let mut socket = socket;
    let Some(Ok(Message::Text(first))) = socket.next().await else {
        return;
    };
    let Ok(message) = decode(first.as_bytes()) else {
        return;
    };
    let ControlMessage::Register {
        token, device_name, ..
    } = message
    else {
        if let ControlMessage::Enroll { code, device_name } = message {
            enroll_loop(socket, state, code, device_name).await;
        }
        return;
    };
    let (mut sink, mut source) = socket.split();
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
    state.plane.session_signal.notify_waiters();
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
    // Push the effective settings (global defaults merged with per-device
    // overrides) so the agent never relies on stale local values.
    if let Some(settings) = load_effective_settings(&state.db, device_id).await {
        if let Ok(payload) = encode(&ControlMessage::SettingsSync { settings }) {
            let _ = out_tx
                .send(Message::Text(
                    String::from_utf8_lossy(&payload).into_owned().into(),
                ))
                .await;
        }
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
                    // Heartbeats only touch memory here; the background flusher
                    // batches them into DB/Redis so a slow or unavailable
                    // datastore can never stall this read loop.
                    state.plane.heartbeats.write().await.insert(
                        device_id,
                        HeartbeatEntry {
                            connection_id,
                            latency_ms: latency_ms as i32,
                            last_seen: Instant::now(),
                        },
                    );
                } else if let Ok(ControlMessage::StreamClose { stream_id, .. }) =
                    decode(text.as_bytes())
                {
                    if let Ok(id) = stream_id.parse::<u128>() {
                        remove_stream_entry(&state.plane, id).await;
                        remove_udp_session(&state.plane, id).await;
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
        let removed = remove_session_if_owned(&mut sessions, device_id, connection_id);
        if removed {
            state.plane.session_signal.notify_waiters();
        }
    }
    {
        let mut heartbeats = state.plane.heartbeats.write().await;
        remove_heartbeat_if_owned(&mut heartbeats, device_id, connection_id);
    }
    drop_invalid_udp_sessions(&state, device_id, connection_id).await;
    teardown_device_data_channels(&state, device_id, connection_id).await;
    let _ = sqlx::query("UPDATE devices SET status='offline' WHERE id=$1")
        .bind(device_id)
        .execute(&state.db)
        .await;
}

/// Pre-registration pairing loop: the agent showed a one-time code and waits
/// on this socket until an admin approves/denies it (or it expires). The
/// server issues the token on approval and hands it back over this socket.
async fn enroll_loop(socket: WebSocket, state: AppState, code: String, device_name: String) {
    let (mut sink, mut source) = socket.split();
    let code = code.trim().to_uppercase();
    if code.len() != ENROLL_CODE_LEN
        || !code
            .bytes()
            .all(|byte| ENROLL_CODE_ALPHABET.contains(&byte))
    {
        let _ = sink
            .send(Message::Text(
                String::from_utf8_lossy(
                    &encode(&ControlMessage::Error {
                        code: "invalid_enroll_code".into(),
                        message: "Enrollment code must be 8 characters".into(),
                    })
                    .unwrap_or_default(),
                )
                .into_owned()
                .into(),
            ))
            .await;
        return;
    }
    let code_hash = hash_token(&code);
    let already_pending = sqlx::query_scalar::<_, i64>(
        "SELECT count(*) FROM enrollments WHERE code_hash=$1 AND status='pending'",
    )
    .bind(&code_hash)
    .fetch_one(&state.db)
    .await
    .unwrap_or(0);
    if already_pending > 0 {
        tracing::warn!("duplicate enrollment code rejected");
        return;
    }
    let enrollment_id = Uuid::new_v4();
    let expires_at = Utc::now() + Duration::minutes(ENROLL_TTL_MINUTES);
    let _ = sqlx::query(
        "INSERT INTO enrollments(id, code_hash, device_name, status, expires_at) \
         VALUES($1,$2,$3,'pending',$4)",
    )
    .bind(enrollment_id)
    .bind(&code_hash)
    .bind(&device_name)
    .bind(expires_at)
    .execute(&state.db)
    .await;
    let (tx, rx) = oneshot::channel::<EnrollmentDecision>();
    state.pending_enrollments.write().await.insert(
        enrollment_id,
        PendingEnrollment {
            code_hash,
            expires_at,
            tx,
        },
    );
    tracing::info!(%enrollment_id, device_name, "agent waiting for enrollment approval");
    let ttl = (expires_at - Utc::now()).to_std().unwrap_or_default();
    let decision = tokio::select! {
        // Socket closed before a decision; the pending row stays until expiry.
        _ = source.next() => {
            state.pending_enrollments.write().await.remove(&enrollment_id);
            return;
        }
        _ = tokio::time::sleep(ttl) => {
            state.pending_enrollments.write().await.remove(&enrollment_id);
            let _ = sqlx::query("UPDATE enrollments SET status='expired' WHERE id=$1 AND status='pending'")
                .bind(enrollment_id)
                .execute(&state.db)
                .await;
            EnrollmentDecision::Expired
        }
        decision = rx => decision.unwrap_or(EnrollmentDecision::Expired),
    };
    match decision {
        EnrollmentDecision::Approved { token, device_id } => {
            if let Ok(payload) = encode(&ControlMessage::Enrolled {
                token,
                device_id: device_id.to_string(),
            }) {
                let _ = sink
                    .send(Message::Text(
                        String::from_utf8_lossy(&payload).into_owned().into(),
                    ))
                    .await;
            }
        }
        EnrollmentDecision::Denied => {
            let _ = sink
                .send(Message::Text(
                    String::from_utf8_lossy(
                        &encode(&ControlMessage::Error {
                            code: "enroll_denied".into(),
                            message: "Enrollment rejected by administrator".into(),
                        })
                        .unwrap_or_default(),
                    )
                    .into_owned()
                    .into(),
                ))
                .await;
        }
        EnrollmentDecision::Expired => {
            let _ = sink
                .send(Message::Text(
                    String::from_utf8_lossy(
                        &encode(&ControlMessage::Error {
                            code: "enroll_expired".into(),
                            message: "Enrollment code expired".into(),
                        })
                        .unwrap_or_default(),
                    )
                    .into_owned()
                    .into(),
                ))
                .await;
        }
    }
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
    let (out_tx, mut out_rx) = mpsc::channel::<Message>(DATA_CHANNEL_QUEUE_FRAMES);
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
    state.plane.data_channel_signal.notify_waiters();
    let writer_plane = state.plane.clone();
    let writer = tokio::spawn(async move {
        while let Some(message) = out_rx.recv().await {
            // The frame has left the shared queue; return the stream's quota
            // so its bridge can enqueue more without monopolizing the queue.
            if let Message::Binary(bytes) = &message {
                if let Ok((id, _)) = decode_stream_data(bytes) {
                    release_stream_slot(&writer_plane, id).await;
                }
            }
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
    let heartbeat_out = out_tx.clone();
    let reader = tokio::spawn(async move {
        let mut last_echo_warn = Instant::now();
        while let Some(Ok(message)) = source.next().await {
            match message {
                Message::Binary(bytes) => {
                    if let Ok((id, data)) = decode_stream_data(&bytes) {
                        match route_stream_data(&reader_state.plane, id, data).await {
                            RouteOutcome::StreamSendTimeout(stream_id) => {
                                send_control(
                                    &reader_state,
                                    device_id,
                                    &ControlMessage::StreamClose {
                                        stream_id: stream_id.to_string(),
                                        reason: Some("stream_send_timeout".into()),
                                    },
                                )
                                .await;
                            }
                            RouteOutcome::StreamChannelClosed(stream_id) => {
                                send_control(
                                    &reader_state,
                                    device_id,
                                    &ControlMessage::StreamClose {
                                        stream_id: stream_id.to_string(),
                                        reason: Some("stream_channel_closed".into()),
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
                // Echo the agent's data-channel heartbeat so the proxy/NAT
                // sees traffic in both directions even when the tunnel is
                // idle; otherwise a long-lived WebSocket gets timed out.
                Message::Text(text) => {
                    if let Ok(ControlMessage::Heartbeat { .. }) = decode(text.as_bytes()) {
                        if let Ok(payload) = encode(&ControlMessage::Heartbeat {
                            version: PROTOCOL_VERSION,
                            latency_ms: 0,
                        }) {
                            match heartbeat_out.try_send(Message::Text(
                                String::from_utf8_lossy(&payload).into_owned().into(),
                            )) {
                                Ok(()) => {}
                                Err(mpsc::error::TrySendError::Full(_)) => {
                                    let now = Instant::now();
                                    if now.duration_since(last_echo_warn)
                                        >= StdDuration::from_secs(ECHO_DROP_WARN_SECS)
                                    {
                                        last_echo_warn = now;
                                        tracing::warn!(
                                            %device_id,
                                            channel_id,
                                            "data channel heartbeat echo dropped; channel queue full"
                                        );
                                    }
                                }
                                Err(mpsc::error::TrySendError::Closed(_)) => {}
                            }
                        }
                    }
                }
                _ => {}
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
        let removed_channel = reader_state
            .plane
            .data_channels
            .write()
            .await
            .get_mut(&device_id)
            .map(|channels| channels.remove(&channel_id));
        if removed_channel.is_some() {
            reader_state.plane.data_channel_signal.notify_waiters();
        }
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
    let generation = state
        .listeners
        .read()
        .await
        .get(&tunnel_id)
        .map(|entry| entry.generation.saturating_add(1))
        .unwrap_or(1);
    if tunnel.kind == "udp" {
        let socket = UdpSocket::bind(("0.0.0.0", tunnel.public_port as u16))
            .await
            .map_err(|e| e.to_string())?;
        let listener_state = state.clone();
        let (exit_tx, mut exit_rx) = oneshot::channel::<()>();
        let handle = tokio::spawn(async move {
            bridge_public_udp(listener_state.clone(), tunnel, socket).await;
            tracing::warn!(
                tunnel_id = %tunnel_id,
                "tunnel listener exited; removed from active listeners"
            );
            finish_listener(listener_state, tunnel_id, generation).await;
            let _ = exit_tx.send(());
        });
        state.listeners.write().await.insert(
            tunnel_id,
            ListenerEntry {
                generation,
                task: handle,
            },
        );
        if exit_rx.try_recv().is_ok() {
            remove_stale_listener_entry(&state, tunnel_id, generation).await;
        }
        return Ok(());
    }
    let listener = TcpListener::bind(("0.0.0.0", tunnel.public_port as u16))
        .await
        .map_err(|e| e.to_string())?;
    let listener_state = state.clone();
    let (exit_tx, mut exit_rx) = oneshot::channel::<()>();
    let handle = tokio::spawn(async move {
        let accept_error = loop {
            match listener.accept().await {
                Ok((socket, _)) => {
                    let st = listener_state.clone();
                    let t = tunnel.clone();
                    tokio::spawn(async move {
                        bridge_public_connection(st, t, socket).await;
                    });
                }
                Err(error) => break error,
            }
        };
        tracing::warn!(
            tunnel_id = %tunnel_id,
            %accept_error,
            "tunnel listener accept failed; removed from active listeners"
        );
        finish_listener(listener_state, tunnel_id, generation).await;
        let _ = exit_tx.send(());
    });
    state.listeners.write().await.insert(
        tunnel_id,
        ListenerEntry {
            generation,
            task: handle,
        },
    );
    if exit_rx.try_recv().is_ok() {
        remove_stale_listener_entry(&state, tunnel_id, generation).await;
    }
    Ok(())
}

/// Removes a listener entry that was installed after its task had already
/// exited (for example accept failed immediately), but only when it still
/// belongs to `generation`.
async fn remove_stale_listener_entry(state: &AppState, tunnel_id: Uuid, generation: u64) {
    let mut listeners = state.listeners.write().await;
    if listeners.get(&tunnel_id).map(|entry| entry.generation) == Some(generation) {
        listeners.remove(&tunnel_id);
    }
}

/// Removes a listener handle from the map only when it still belongs to the
/// generation this task started with, so an exiting task never deletes a
/// handle installed by a newer `start_listener`.
async fn finish_listener(state: AppState, tunnel_id: Uuid, generation: u64) {
    let remove = state
        .listeners
        .read()
        .await
        .get(&tunnel_id)
        .map(|entry| entry.generation == generation)
        .unwrap_or(false);
    if remove {
        state.listeners.write().await.remove(&tunnel_id);
    }
}

/// Periodically re-checks every enabled tunnel and restarts listeners that
/// exited (for example after an accept error), so a tunnel never stays dead
/// in the admin console until an admin toggles it.
async fn reconcile_listeners(state: AppState) {
    let mut ticker = tokio::time::interval(StdDuration::from_secs(LISTENER_RECONCILE_SECS));
    ticker.tick().await; // skip the immediate first tick
    loop {
        ticker.tick().await;
        if !state.accepting.load(Ordering::Relaxed) {
            return;
        }
        let enabled: Vec<Uuid> = sqlx::query_scalar("SELECT id FROM tunnels WHERE enabled")
            .fetch_all(&state.db)
            .await
            .unwrap_or_default();
        for tunnel_id in enabled {
            if state.listeners.read().await.contains_key(&tunnel_id) {
                continue;
            }
            match start_listener(state.clone(), tunnel_id).await {
                Ok(()) => {
                    tracing::info!(
                        tunnel_id = %tunnel_id,
                        "tunnel listener restarted by reconciliation"
                    );
                }
                Err(error) => {
                    tracing::warn!(
                        tunnel_id = %tunnel_id,
                        %error,
                        "tunnel listener reconciliation failed; will retry"
                    );
                }
            }
        }
    }
}
async fn bridge_public_connection(
    state: AppState,
    tunnel: TunnelRecord,
    socket: tokio::net::TcpStream,
) {
    // Interactive protocols (SSH, HTTP, RDP) suffer from Nagle + delayed ACK
    // on small packets; disable Nagle on the public socket right away.
    let _ = socket.set_nodelay(true);
    if !state.accepting.load(Ordering::Relaxed) {
        return;
    }
    // The control session can be registered while the agent's data channels
    // are still binding (every reconnect). Wait briefly for a channel instead
    // of rejecting the connection; the wait is bounded and aborts early if
    // the control session disappears.
    let Some(channel_id) = wait_for_data_channel(&state.plane, tunnel.device_id).await else {
        return;
    };
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
    let Some(channel) = state
        .plane
        .data_channels
        .read()
        .await
        .get(&tunnel.device_id)
        .and_then(|channels| channels.get(&channel_id))
        .filter(|channel| channel.connection_id == session.connection_id)
        .cloned()
    else {
        return;
    };
    let id = Uuid::new_v4().as_u128();
    let (mut reader, mut writer) = socket.into_split();
    let (incoming_tx, mut incoming_rx) = mpsc::channel::<Vec<u8>>(STREAM_QUEUE_FRAMES);
    if !try_register_stream(
        &state.plane,
        id,
        tunnel.device_id,
        tunnel.id,
        channel_id,
        incoming_tx,
        tunnel.max_connections as usize,
    )
    .await
    {
        // The tunnel is at its connection limit; reject the new connection by
        // dropping the socket without registering a stream or sending
        // `StreamOpen`.
        return;
    }
    // StreamOpen must be queued or the agent never learns about the stream;
    // wait briefly for queue space, but never hang the bridge on a congested
    // control socket.
    let open = ControlMessage::StreamOpen {
        stream_id: id.to_string(),
        tunnel_id: tunnel.id.to_string(),
        data_channel: channel_id,
    };
    if !send_control_to_session(&session, &open, Some(STREAM_OPEN_SEND_TIMEOUT)).await {
        // The control queue stayed full or the session died; drop the stream
        // entry so no orphan registration is left behind.
        remove_stream_entry(&state.plane, id).await;
        return;
    }
    let out = channel.tx;
    let slot = {
        let streams = state.plane.streams.read().await;
        streams.get(&id).map(|entry| entry.slot.clone())
    };
    let inbound = tokio::spawn(async move {
        while let Some(data) = incoming_rx.recv().await {
            // The agent already throttled this direction at its source; do
            // not charge the same bytes again on the way out.
            if writer.write_all(&data).await.is_err() {
                break;
            }
        }
    });
    let mut buf = [0_u8; TCP_CHUNK_SIZE];
    loop {
        match tokio::io::AsyncReadExt::read(&mut reader, &mut buf).await {
            Ok(0) | Err(_) => break,
            Ok(n) => {
                state.bandwidth.acquire(tunnel.device_id, n).await;
                let Ok(frame) = encode_stream_data(id, &buf[..n]) else {
                    break;
                };
                // Hold this stream's share of the channel queue while the
                // frame waits; one bulk stream can never fill the queue.
                if let Some(slot) = &slot {
                    if !acquire_stream_slot(&state.plane, slot, id).await {
                        break;
                    }
                }
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
    remove_stream_entry(&state.plane, id).await;
    inbound.abort();
}

/// Stops a tunnel listener and drops any UDP sessions bound to it.
async fn remove_listener(state: &AppState, tunnel_id: Uuid) {
    if let Some(entry) = state.listeners.write().await.remove(&tunnel_id) {
        entry.task.abort();
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
        remove_udp_session(&state.plane, id).await;
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
        remove_udp_session(&state.plane, id).await;
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
                state.bandwidth.acquire(tunnel.device_id, size).await;
                let stream_id = {
                    let peers = state.plane.udp_peers.read().await;
                    peers
                        .get(&tunnel.id)
                        .and_then(|peers| peers.get(&peer))
                        .copied()
                };
                let stream_id = match stream_id {
                    Some(id) => id,
                    None => {
                        let active = state
                            .plane
                            .udp_peers
                            .read()
                            .await
                            .get(&tunnel.id)
                            .map(|peers| peers.len())
                            .unwrap_or(0);
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
                        let Some(channel_id) =
                            pick_data_channel(&state.plane, tunnel.device_id).await
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
                        tokio::spawn(async move {
                            while let Some(data) = outbox_rx.recv().await {
                                // Agent-side throttling already charged this
                                // direction; the server must not charge twice.
                                if send_socket.send_to(&data, send_peer).await.is_err() {
                                    break;
                                }
                            }
                        });
                        insert_udp_session(
                            &state.plane,
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
                        )
                        .await;
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
                    remove_udp_session(&state.plane, id).await;
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
