//! Versioned messages exchanged between the control plane and Windows agents.

use serde::{Deserialize, Serialize};
use thiserror::Error;

pub const PROTOCOL_VERSION: u16 = 4;
pub const MAX_FRAME_BYTES: usize = 1024 * 1024;
/// Payload bytes read from a TCP socket into one data frame. Larger chunks
/// cut syscall/allocation/frame-header overhead while staying well under the
/// frame cap.
pub const TCP_CHUNK_SIZE: usize = 64 * 1024;

/// Runtime parameters the server pushes to an agent. The server is the source
/// of truth: local bootstrap values only cover the first connection, after
/// which `SettingsSync` replaces them.
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
pub struct AgentSettings {
    pub device_name: String,
    pub server_url: String,
    pub data_channels: u16,
    pub heartbeat_secs: u64,
    pub pong_timeout_secs: u64,
    pub reconnect_min_secs: u64,
    pub reconnect_max_secs: u64,
    pub log_level: String,
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
#[serde(rename_all = "snake_case", tag = "type")]
pub enum ControlMessage {
    Register {
        version: u16,
        token: String,
        device_name: String,
    },
    Registered {
        device_id: String,
        tunnels: Vec<TunnelSpec>,
    },
    Heartbeat {
        version: u16,
        latency_ms: u32,
    },
    /// Pre-registration pairing request: the agent shows an 8-character code
    /// on its console; the admin enters it in the management console to prove
    /// physical access before the server issues a device token.
    Enroll {
        code: String,
        device_name: String,
    },
    /// Server -> agent reply to a successful enrollment. The agent persists
    /// the token locally, disconnects, and re-registers through `Register`.
    Enrolled {
        token: String,
        device_id: String,
    },
    SyncTunnels {
        tunnels: Vec<TunnelSpec>,
    },
    /// Server pushes the device's effective settings (global defaults merged
    /// with per-device overrides). The agent applies live where possible and
    /// reconnects for fields that require it (server_url, data_channels).
    SettingsSync {
        settings: AgentSettings,
    },
    /// Server rotates the device's access token; the agent persists it and
    /// reconnects. Old tokens are already revoked server-side.
    TokenRotate {
        token: String,
    },
    StreamOpen {
        stream_id: String,
        tunnel_id: String,
        /// Data channel assigned by the server. The agent routes all data
        /// frames for this stream through the matching WebSocket.
        data_channel: u16,
    },
    StreamClose {
        stream_id: String,
        reason: Option<String>,
    },
    /// Asks the agent to verify it can reach the tunnel's local service.
    ProbeLocal {
        probe_id: String,
        tunnel_id: String,
    },
    ProbeResult {
        probe_id: String,
        ok: bool,
        message: Option<String>,
    },
    /// Server pushes its current bandwidth cap to the agent so the agent can
    /// throttle its own agent -> server data at the source; the server does
    /// not charge that direction again. 0 disables throttling.
    BandwidthConfig {
        mbps: u64,
    },
    /// Server asks the agent to restart its process. The agent replies with
    /// `RestartProgress` until it exits; service-mode agents rely on the SCM
    /// failure recovery to come back, while console-mode agents spawn a
    /// fresh hidden worker before exiting.
    RestartAgent {
        restart_id: String,
        reason: Option<String>,
    },
    /// Agent -> server progress updates for a remote restart. Older agents
    /// simply ignore `RestartAgent` (unknown serde variants decode as
    /// errors), so the server must time out the restart when no progress is
    /// heard.
    RestartProgress {
        restart_id: String,
        progress: u8,
        phase: String,
        message: Option<String>,
    },
    /// First message on a data WebSocket: binds the socket to an online
    /// device using the same agent token as the control registration.
    DataBind {
        token: String,
    },
    /// Server -> agent reply on a data WebSocket, assigning its channel id.
    DataBound {
        channel_id: u16,
    },
    Error {
        code: String,
        message: String,
    },
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
pub struct TunnelSpec {
    pub id: String,
    pub name: String,
    pub kind: TunnelKind,
    pub public_port: u16,
    pub local_host: String,
    pub local_port: u16,
    pub enabled: bool,
    pub max_connections: u16,
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
#[serde(rename_all = "lowercase")]
pub enum TunnelKind {
    Tcp,
    Http,
    Udp,
}

#[derive(Debug, Error, PartialEq, Eq)]
pub enum ProtocolError {
    #[error("frame exceeds {MAX_FRAME_BYTES} bytes")]
    FrameTooLarge,
    #[error("unsupported protocol version {0}")]
    UnsupportedVersion(u16),
    #[error("invalid control message: {0}")]
    InvalidMessage(String),
}

pub fn encode(message: &ControlMessage) -> Result<Vec<u8>, ProtocolError> {
    let bytes =
        serde_json::to_vec(message).map_err(|e| ProtocolError::InvalidMessage(e.to_string()))?;
    if bytes.len() > MAX_FRAME_BYTES {
        return Err(ProtocolError::FrameTooLarge);
    }
    Ok(bytes)
}

pub fn decode(bytes: &[u8]) -> Result<ControlMessage, ProtocolError> {
    if bytes.len() > MAX_FRAME_BYTES {
        return Err(ProtocolError::FrameTooLarge);
    }
    let message = serde_json::from_slice::<ControlMessage>(bytes)
        .map_err(|e| ProtocolError::InvalidMessage(e.to_string()))?;
    let version = match &message {
        ControlMessage::Register { version, .. } | ControlMessage::Heartbeat { version, .. } => {
            *version
        }
        _ => PROTOCOL_VERSION,
    };
    if version != PROTOCOL_VERSION {
        return Err(ProtocolError::UnsupportedVersion(version));
    }
    Ok(message)
}

/// WebSocket text frames carry control messages; binary frames carry stream data.
/// The 16-byte stream identifier is followed by the raw payload, avoiding JSON/base64
/// overhead on the data plane.
pub fn encode_stream_data(stream_id: u128, data: &[u8]) -> Result<Vec<u8>, ProtocolError> {
    if data.len() + 16 > MAX_FRAME_BYTES {
        return Err(ProtocolError::FrameTooLarge);
    }
    let mut frame = Vec::with_capacity(16 + data.len());
    frame.extend_from_slice(&stream_id.to_be_bytes());
    frame.extend_from_slice(data);
    Ok(frame)
}

pub fn decode_stream_data(frame: &[u8]) -> Result<(u128, &[u8]), ProtocolError> {
    if frame.len() < 16 || frame.len() > MAX_FRAME_BYTES {
        return Err(ProtocolError::InvalidMessage("invalid stream frame".into()));
    }
    let mut id = [0_u8; 16];
    id.copy_from_slice(&frame[..16]);
    Ok((u128::from_be_bytes(id), &frame[16..]))
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn tcp_chunk_size_fits_frame_cap() {
        assert!(
            TCP_CHUNK_SIZE + 16 <= MAX_FRAME_BYTES,
            "one 64KiB TCP chunk plus the 16-byte stream header must fit a frame"
        );
    }

    #[test]
    fn round_trip_message() {
        let input = ControlMessage::Heartbeat {
            version: PROTOCOL_VERSION,
            latency_ms: 14,
        };
        assert_eq!(decode(&encode(&input).unwrap()).unwrap(), input);
    }
    #[test]
    fn round_trip_restart_messages() {
        let request = ControlMessage::RestartAgent {
            restart_id: "b6f9d6c2-4f80-4f7a-9f5b-8e8f4d0f2c3a".into(),
            reason: Some("admin_request".into()),
        };
        assert_eq!(decode(&encode(&request).unwrap()).unwrap(), request);
        let progress = ControlMessage::RestartProgress {
            restart_id: "b6f9d6c2-4f80-4f7a-9f5b-8e8f4d0f2c3a".into(),
            progress: 30,
            phase: "stopping".into(),
            message: Some("agent is stopping".into()),
        };
        assert_eq!(decode(&encode(&progress).unwrap()).unwrap(), progress);
    }
    #[test]
    fn rejects_wrong_version() {
        assert_eq!(
            decode(br#"{"type":"heartbeat","version":1,"latency_ms":1}"#),
            Err(ProtocolError::UnsupportedVersion(1))
        );
    }
    #[test]
    fn rejects_v3_heartbeat() {
        assert_eq!(
            decode(br#"{"type":"heartbeat","version":3,"latency_ms":1}"#),
            Err(ProtocolError::UnsupportedVersion(3))
        );
    }
    #[test]
    fn enroll_round_trip() {
        let input = ControlMessage::Enroll {
            code: "AB12CD34".into(),
            device_name: "DESKTOP-01".into(),
        };
        assert_eq!(decode(&encode(&input).unwrap()).unwrap(), input);
    }
    #[test]
    fn enrolled_round_trip() {
        let input = ControlMessage::Enrolled {
            token: "abc123".into(),
            device_id: "device-1".into(),
        };
        assert_eq!(decode(&encode(&input).unwrap()).unwrap(), input);
    }
    #[test]
    fn settings_sync_round_trip() {
        let input = ControlMessage::SettingsSync {
            settings: AgentSettings {
                device_name: "DESKTOP-01".into(),
                server_url: "ws://203.0.113.10:18080/control".into(),
                data_channels: 4,
                heartbeat_secs: 10,
                pong_timeout_secs: 25,
                reconnect_min_secs: 1,
                reconnect_max_secs: 10,
                log_level: "debug".into(),
            },
        };
        assert_eq!(decode(&encode(&input).unwrap()).unwrap(), input);
    }
    #[test]
    fn token_rotate_round_trip() {
        let input = ControlMessage::TokenRotate {
            token: "new-token".into(),
        };
        assert_eq!(decode(&encode(&input).unwrap()).unwrap(), input);
    }
    #[test]
    fn udp_tunnel_spec_round_trip() {
        let spec = TunnelSpec {
            id: "tunnel-1".into(),
            name: "Bedrock server".into(),
            kind: TunnelKind::Udp,
            public_port: 19132,
            local_host: "127.0.0.1".into(),
            local_port: 19132,
            enabled: true,
            max_connections: 50,
        };
        let encoded = encode(&ControlMessage::Registered {
            device_id: "device-1".into(),
            tunnels: vec![spec.clone()],
        })
        .unwrap();
        assert_eq!(
            decode(&encoded).unwrap(),
            ControlMessage::Registered {
                device_id: "device-1".into(),
                tunnels: vec![spec],
            }
        );
    }
    #[test]
    fn probe_messages_round_trip() {
        let input = ControlMessage::ProbeLocal {
            probe_id: "probe-1".into(),
            tunnel_id: "tunnel-1".into(),
        };
        assert_eq!(decode(&encode(&input).unwrap()).unwrap(), input);
        let result = ControlMessage::ProbeResult {
            probe_id: "probe-1".into(),
            ok: true,
            message: Some("local tcp reachable".into()),
        };
        assert_eq!(decode(&encode(&result).unwrap()).unwrap(), result);
    }
    #[test]
    fn stream_open_carries_data_channel() {
        let input = ControlMessage::StreamOpen {
            stream_id: "stream-1".into(),
            tunnel_id: "tunnel-1".into(),
            data_channel: 2,
        };
        assert_eq!(decode(&encode(&input).unwrap()).unwrap(), input);
        let text = String::from_utf8(encode(&input).unwrap()).unwrap();
        assert!(text.contains("\"data_channel\":2"));
    }
    #[test]
    fn data_bind_bound_round_trip() {
        let bind = ControlMessage::DataBind {
            token: "agent-token".into(),
        };
        assert_eq!(decode(&encode(&bind).unwrap()).unwrap(), bind);
        let bound = ControlMessage::DataBound { channel_id: 1 };
        assert_eq!(decode(&encode(&bound).unwrap()).unwrap(), bound);
    }
    #[test]
    fn bandwidth_config_round_trip() {
        let input = ControlMessage::BandwidthConfig { mbps: 3 };
        assert_eq!(decode(&encode(&input).unwrap()).unwrap(), input);
    }
}
