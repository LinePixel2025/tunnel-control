use argon2::PasswordHasher;
use axum::{
    Json, Router,
    extract::{
        Path, State,
        ws::{Message, WebSocket, WebSocketUpgrade},
    },
    http::{HeaderMap, StatusCode, header},
    response::IntoResponse,
    routing::{get, post},
};
use chrono::{Duration, Utc};
use futures_util::{SinkExt, StreamExt};
use jsonwebtoken::{
    DecodingKey, EncodingKey, Header, Validation, decode as jwt_decode, encode as jwt_encode,
};
use redis::AsyncCommands;
use serde::{Deserialize, Serialize};
use sha2::Digest;
use sqlx::{FromRow, PgPool, postgres::PgPoolOptions};
use std::{collections::HashMap, env, sync::Arc};
use tokio::{
    io::AsyncWriteExt,
    net::TcpListener,
    sync::{RwLock, mpsc},
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
    sessions: Arc<RwLock<HashMap<Uuid, mpsc::Sender<Message>>>>,
    streams: Arc<RwLock<HashMap<u128, mpsc::Sender<Vec<u8>>>>>,
    listeners: Arc<RwLock<HashMap<Uuid, tokio::task::JoinHandle<()>>>>,
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
    let state = AppState {
        db,
        redis: redis::Client::open(redis_url)?,
        jwt_secret: Arc::new(env::var("JWT_SECRET").expect("JWT_SECRET is required")),
        sessions: Arc::new(RwLock::new(HashMap::new())),
        streams: Arc::new(RwLock::new(HashMap::new())),
        listeners: Arc::new(RwLock::new(HashMap::new())),
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
        .route("/api/v1/devices", get(list_devices))
        .route("/api/v1/tunnels", get(list_tunnels).post(create_tunnel))
        .route("/api/v1/tunnels/{id}/toggle", post(toggle_tunnel))
        .route("/control", get(control_socket))
        .layer(CorsLayer::permissive())
        .layer(TraceLayer::new_for_http())
        .with_state(state);
    let port = env::var("MANAGEMENT_PORT")
        .unwrap_or_else(|_| "8080".into())
        .parse()?;
    let listener = TcpListener::bind(("0.0.0.0", port)).await?;
    tracing::info!(port, "management and control listener ready");
    axum::serve(listener, app).await?;
    Ok(())
}

async fn bootstrap_admin(db: &PgPool) -> anyhow::Result<()> {
    let (Ok(email), Ok(password)) = (
        env::var("BOOTSTRAP_ADMIN_EMAIL"),
        env::var("BOOTSTRAP_ADMIN_PASSWORD"),
    ) else {
        return Ok(());
    };
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
        sqlx::query_as("SELECT id, password_hash, role FROM users WHERE email = $1")
            .bind(&input.email)
            .fetch_optional(&state.db)
            .await
            .map_err(|_| StatusCode::INTERNAL_SERVER_ERROR)?
            .ok_or(StatusCode::UNAUTHORIZED)?;
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
        return Err(StatusCode::UNAUTHORIZED);
    }
    let claims = Claims {
        sub: user.0.to_string(),
        role: user.2,
        exp: (Utc::now() + Duration::hours(8)).timestamp() as usize,
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
    if !(10000..=60000).contains(&input.public_port) {
        return Err((
            StatusCode::UNPROCESSABLE_ENTITY,
            "Public port must be between 10000 and 60000".into(),
        ));
    }
    let kind = match input.kind {
        TunnelKind::Tcp => "tcp",
        TunnelKind::Http => "http",
    };
    let id = Uuid::new_v4();
    let result = sqlx::query("INSERT INTO tunnels(id,name,kind,public_port,local_host,local_port,enabled,max_connections,device_id) VALUES($1,$2,$3,$4,$5,$6,true,$7,$8)").bind(id).bind(&input.name).bind(kind).bind(input.public_port as i32).bind(&input.local_host).bind(input.local_port as i32).bind(input.max_connections.unwrap_or(100) as i32).bind(input.device_id).execute(&state.db).await;
    if result.is_err() {
        return Err((
            StatusCode::CONFLICT,
            "Public port is unavailable or device does not exist".into(),
        ));
    }
    audit(&state.db, actor.id, "tunnel.created", &input.name).await;
    let tunnel = get_tunnel(&state.db, id).await.map_err(|_| {
        (
            StatusCode::INTERNAL_SERVER_ERROR,
            "Could not create tunnel".into(),
        )
    })?;
    start_listener(state.clone(), tunnel.id)
        .await
        .map_err(|e| (StatusCode::INTERNAL_SERVER_ERROR, e))?;
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
    audit(&state.db, actor.id, "tunnel.toggled", &tunnel.name).await;
    if tunnel.enabled {
        start_listener(state.clone(), id)
            .await
            .map_err(|_| StatusCode::INTERNAL_SERVER_ERROR)?;
    } else if let Some(task) = state.listeners.write().await.remove(&id) {
        task.abort();
    }
    Ok(Json(tunnel))
}
async fn get_tunnel(db: &PgPool, id: Uuid) -> Result<TunnelRecord, sqlx::Error> {
    sqlx::query_as::<_,TunnelRecord>("SELECT t.id,t.name,t.kind,t.public_port,t.local_host,t.local_port,t.enabled,t.max_connections,t.device_id,CASE WHEN d.status='online' THEN 'ready' ELSE 'offline' END status,0::bigint connections FROM tunnels t JOIN devices d ON d.id=t.device_id WHERE t.id=$1").bind(id).fetch_one(db).await
}
async fn audit(db: &PgPool, actor: Uuid, action: &str, subject: &str) {
    let _ = sqlx::query("INSERT INTO audit_events(id,actor_id,action,subject) VALUES($1,$2,$3,$4)")
        .bind(Uuid::new_v4())
        .bind(actor)
        .bind(action)
        .bind(subject)
        .execute(db)
        .await;
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
    let device:Option<Uuid>=sqlx::query_scalar("SELECT device_id FROM access_tokens WHERE token_hash=$1 AND revoked_at IS NULL AND (expires_at IS NULL OR expires_at>now())").bind(token_hash).fetch_optional(&state.db).await.ok().flatten();
    let Some(device_id) = device else {
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
    };
    let _ =
        sqlx::query("UPDATE devices SET name=$1,status='online',last_seen_at=now() WHERE id=$2")
            .bind(device_name)
            .bind(device_id)
            .execute(&state.db)
            .await;
    let (out_tx, mut out_rx) = mpsc::channel::<Message>(256);
    state
        .sessions
        .write()
        .await
        .insert(device_id, out_tx.clone());
    if let Ok(mut redis) = state.redis.get_multiplexed_tokio_connection().await {
        let _: Result<(), _> = redis.set_ex(format!("online:{device_id}"), "1", 45).await;
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
                    let _=sqlx::query("UPDATE devices SET latency_ms=$1,last_seen_at=now(),status='online' WHERE id=$2").bind(latency_ms as i32).bind(device_id).execute(&state.db).await;
                }
            }
            Message::Binary(bytes) => {
                if let Ok((id, data)) = decode_stream_data(&bytes) {
                    if let Some(tx) = state.streams.read().await.get(&id).cloned() {
                        let _ = tx.send(data.to_vec()).await;
                    }
                }
            }
            _ => {}
        }
    }
    writer.abort();
    state.sessions.write().await.remove(&device_id);
    let _ = sqlx::query("UPDATE devices SET status='offline' WHERE id=$1")
        .bind(device_id)
        .execute(&state.db)
        .await;
}
async fn load_specs(db: &PgPool, device_id: Uuid) -> Vec<TunnelSpec> {
    sqlx::query_as::<_,(Uuid,String,String,i32,String,i32,bool,i32)>("SELECT id,name,kind,public_port,local_host,local_port,enabled,max_connections FROM tunnels WHERE device_id=$1 AND enabled").bind(device_id).fetch_all(db).await.unwrap_or_default().into_iter().map(|r|TunnelSpec{id:r.0.to_string(),name:r.1,kind:if r.2=="http"{TunnelKind::Http}else{TunnelKind::Tcp},public_port:r.3 as u16,local_host:r.4,local_port:r.5 as u16,enabled:r.6,max_connections:r.7 as u16}).collect()
}
async fn start_listener(state: AppState, tunnel_id: Uuid) -> Result<(), String> {
    if state.listeners.read().await.contains_key(&tunnel_id) {
        return Ok(());
    }
    let tunnel = get_tunnel(&state.db, tunnel_id)
        .await
        .map_err(|e| e.to_string())?;
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
    let Some(session) = state.sessions.read().await.get(&tunnel.device_id).cloned() else {
        return;
    };
    let id = Uuid::new_v4().as_u128();
    let (mut reader, mut writer) = socket.into_split();
    let (incoming_tx, mut incoming_rx) = mpsc::channel::<Vec<u8>>(128);
    state.streams.write().await.insert(id, incoming_tx);
    if session
        .send(Message::Text(
            String::from_utf8(
                encode(&ControlMessage::StreamOpen {
                    stream_id: id.to_string(),
                    tunnel_id: tunnel.id.to_string(),
                })
                .unwrap(),
            )
            .unwrap()
            .into(),
        ))
        .await
        .is_err()
    {
        state.streams.write().await.remove(&id);
        return;
    }
    let out = session.clone();
    let inbound = tokio::spawn(async move {
        while let Some(data) = incoming_rx.recv().await {
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
                let Ok(frame) = encode_stream_data(id, &buf[..n]) else {
                    break;
                };
                if out.send(Message::Binary(frame.into())).await.is_err() {
                    break;
                }
            }
        }
    }
    let _ = session
        .send(Message::Text(
            String::from_utf8(
                encode(&ControlMessage::StreamClose {
                    stream_id: id.to_string(),
                    reason: None,
                })
                .unwrap(),
            )
            .unwrap()
            .into(),
        ))
        .await;
    state.streams.write().await.remove(&id);
    inbound.abort();
}
