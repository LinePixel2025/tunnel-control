//! Versioned messages exchanged between the control plane and Windows agents.

use serde::{Deserialize, Serialize};
use thiserror::Error;

pub const PROTOCOL_VERSION: u16 = 1;
pub const MAX_FRAME_BYTES: usize = 1024 * 1024;

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
    SyncTunnels {
        tunnels: Vec<TunnelSpec>,
    },
    StreamOpen {
        stream_id: String,
        tunnel_id: String,
    },
    StreamData {
        stream_id: String,
        data: Vec<u8>,
    },
    StreamClose {
        stream_id: String,
        reason: Option<String>,
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
    fn round_trip_message() {
        let input = ControlMessage::Heartbeat {
            version: PROTOCOL_VERSION,
            latency_ms: 14,
        };
        assert_eq!(decode(&encode(&input).unwrap()).unwrap(), input);
    }
    #[test]
    fn rejects_wrong_version() {
        assert_eq!(
            decode(br#"{"type":"heartbeat","version":99,"latency_ms":1}"#),
            Err(ProtocolError::UnsupportedVersion(99))
        );
    }
}
