//! Specular Protocol Definitions
//!
//! Wire protocol for client <-> relay communication.

use ed25519_dalek::{Signature, Signer, SigningKey, VerifyingKey};
use serde::{Deserialize, Serialize};
use serde_big_array::BigArray;
use thiserror::Error;

/// Protocol magic bytes: "SPEC" in ASCII
pub const MAGIC: [u8; 4] = [0x53, 0x50, 0x45, 0x43];

/// Protocol version
pub const VERSION: u8 = 1;

/// Default relay control port (UDP)
pub const CONTROL_PORT: u16 = 7433;

/// Registration TTL in seconds
pub const DEFAULT_TTL: u32 = 3600; // 1 hour

/// Heartbeat interval in seconds
pub const HEARTBEAT_INTERVAL: u32 = 30;

/// Maximum ports per IP (quota)
pub const MAX_PORTS_PER_IP: u32 = 3;

/// Rate limit: bytes per second
pub const RATE_LIMIT_BPS: u64 = 1_000_000_000; // 1 Gbps

/// Burst size in bytes
pub const BURST_SIZE: u64 = 10_485_760; // 10 MB

#[derive(Error, Debug)]
pub enum ProtocolError {
    #[error("Invalid magic bytes")]
    InvalidMagic,
    #[error("Unsupported version: {0}")]
    UnsupportedVersion(u8),
    #[error("Invalid message type: {0}")]
    InvalidMessageType(u8),
    #[error("Signature verification failed")]
    SignatureInvalid,
    #[error("Serialization error: {0}")]
    Serialization(String),
    #[error("Challenge mismatch")]
    ChallengeMismatch,
    #[error("Registration not found")]
    NotFound,
    #[error("Quota exceeded")]
    QuotaExceeded,
    #[error("Port already registered")]
    PortInUse,
}

/// Message types for the control protocol
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[repr(u8)]
pub enum MessageType {
    /// Client -> Relay: Request port registration
    Register = 0x01,
    /// Relay -> Client: Challenge to prove reachability
    Challenge = 0x02,
    /// Client -> Relay: Response to challenge
    Response = 0x03,
    /// Relay -> Client: Registration confirmed
    Ack = 0x04,
    /// Client -> Relay: Keep registration alive
    Heartbeat = 0x05,
    /// Relay -> Client: Heartbeat acknowledged
    HeartbeatAck = 0x06,
    /// Relay -> Client: Error response
    ErrorResponse = 0xFF,
}

impl TryFrom<u8> for MessageType {
    type Error = ProtocolError;

    fn try_from(value: u8) -> Result<Self, Self::Error> {
        match value {
            0x01 => Ok(MessageType::Register),
            0x02 => Ok(MessageType::Challenge),
            0x03 => Ok(MessageType::Response),
            0x04 => Ok(MessageType::Ack),
            0x05 => Ok(MessageType::Heartbeat),
            0x06 => Ok(MessageType::HeartbeatAck),
            0xFF => Ok(MessageType::ErrorResponse),
            _ => Err(ProtocolError::InvalidMessageType(value)),
        }
    }
}

/// Wire format header (12 bytes)
///
/// ```text
/// 0       4       5       6       8       12
/// +-------+-------+-------+-------+-------+
/// | MAGIC | VER   | TYPE  | LEN   | SEQ   |
/// +-------+-------+-------+-------+-------+
/// ```
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct Header {
    pub magic: [u8; 4],
    pub version: u8,
    pub msg_type: u8,
    pub length: u16,
    pub sequence: u32,
}

impl Header {
    pub fn new(msg_type: MessageType, length: u16, sequence: u32) -> Self {
        Self {
            magic: MAGIC,
            version: VERSION,
            msg_type: msg_type as u8,
            length,
            sequence,
        }
    }

    pub fn validate(&self) -> Result<MessageType, ProtocolError> {
        if self.magic != MAGIC {
            return Err(ProtocolError::InvalidMagic);
        }
        if self.version != VERSION {
            return Err(ProtocolError::UnsupportedVersion(self.version));
        }
        MessageType::try_from(self.msg_type)
    }
}

/// Registration request from client
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct RegisterMessage {
    /// Requested port (0 = auto-assign)
    pub port: u16,
    /// Client's public key (32 bytes)
    #[serde(with = "BigArray")]
    pub pubkey: [u8; 32],
    /// Signature over (port || pubkey || timestamp)
    #[serde(with = "BigArray")]
    pub signature: [u8; 64],
    /// Unix timestamp
    pub timestamp: u64,
}

impl RegisterMessage {
    pub fn new(port: u16, signing_key: &SigningKey, timestamp: u64) -> Self {
        let pubkey = signing_key.verifying_key().to_bytes();

        // Sign: port || pubkey || timestamp
        let mut msg = Vec::with_capacity(2 + 32 + 8);
        msg.extend_from_slice(&port.to_le_bytes());
        msg.extend_from_slice(&pubkey);
        msg.extend_from_slice(&timestamp.to_le_bytes());

        let signature = signing_key.sign(&msg);

        Self {
            port,
            pubkey,
            signature: signature.to_bytes(),
            timestamp,
        }
    }

    pub fn verify(&self) -> Result<VerifyingKey, ProtocolError> {
        let pubkey = VerifyingKey::from_bytes(&self.pubkey)
            .map_err(|_| ProtocolError::SignatureInvalid)?;

        let mut msg = Vec::with_capacity(2 + 32 + 8);
        msg.extend_from_slice(&self.port.to_le_bytes());
        msg.extend_from_slice(&self.pubkey);
        msg.extend_from_slice(&self.timestamp.to_le_bytes());

        let signature = Signature::from_bytes(&self.signature);

        pubkey
            .verify_strict(&msg, &signature)
            .map_err(|_| ProtocolError::SignatureInvalid)?;

        Ok(pubkey)
    }
}

/// Challenge from relay to prove client reachability
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ChallengeMessage {
    /// Random nonce (32 bytes)
    #[serde(with = "BigArray")]
    pub nonce: [u8; 32],
    /// Assigned port
    pub port: u16,
}

impl ChallengeMessage {
    pub fn new(port: u16) -> Self {
        let mut nonce = [0u8; 32];
        rand::RngCore::fill_bytes(&mut rand::thread_rng(), &mut nonce);
        Self { nonce, port }
    }
}

/// Response to challenge
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ResponseMessage {
    /// Echo back the nonce
    #[serde(with = "BigArray")]
    pub nonce: [u8; 32],
    /// Port being registered
    pub port: u16,
    /// Signature over nonce
    #[serde(with = "BigArray")]
    pub signature: [u8; 64],
}

impl ResponseMessage {
    pub fn new(nonce: [u8; 32], port: u16, signing_key: &SigningKey) -> Self {
        let signature = signing_key.sign(&nonce);
        Self {
            nonce,
            port,
            signature: signature.to_bytes(),
        }
    }

    pub fn verify(&self, pubkey: &VerifyingKey, expected_nonce: &[u8; 32]) -> Result<(), ProtocolError> {
        if &self.nonce != expected_nonce {
            return Err(ProtocolError::ChallengeMismatch);
        }

        let signature = Signature::from_bytes(&self.signature);
        pubkey
            .verify_strict(&self.nonce, &signature)
            .map_err(|_| ProtocolError::SignatureInvalid)
    }
}

/// Registration acknowledgment
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct AckMessage {
    /// Confirmed port
    pub port: u16,
    /// TTL in seconds
    pub ttl: u32,
    /// Relay's public IP (for client to verify)
    pub relay_ip: [u8; 4],
}

/// Heartbeat to keep registration alive
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct HeartbeatMessage {
    /// Registered port
    pub port: u16,
    /// Signature over (port || timestamp)
    #[serde(with = "BigArray")]
    pub signature: [u8; 64],
    /// Unix timestamp
    pub timestamp: u64,
}

impl HeartbeatMessage {
    pub fn new(port: u16, signing_key: &SigningKey, timestamp: u64) -> Self {
        let mut msg = Vec::with_capacity(2 + 8);
        msg.extend_from_slice(&port.to_le_bytes());
        msg.extend_from_slice(&timestamp.to_le_bytes());

        let signature = signing_key.sign(&msg);

        Self {
            port,
            signature: signature.to_bytes(),
            timestamp,
        }
    }
}

/// Heartbeat acknowledgment
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct HeartbeatAckMessage {
    pub port: u16,
    pub ttl: u32,
}

/// Error response
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ErrorMessage {
    pub code: u16,
    pub message: String,
}

/// Error codes
pub mod error_codes {
    pub const QUOTA_EXCEEDED: u16 = 1;
    pub const PORT_IN_USE: u16 = 2;
    pub const INVALID_SIGNATURE: u16 = 3;
    pub const NOT_FOUND: u16 = 4;
    pub const RATE_LIMITED: u16 = 5;
    pub const INTERNAL_ERROR: u16 = 255;
}

/// Registration state in eBPF map
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
#[repr(u8)]
pub enum RegistrationState {
    /// Waiting for challenge response
    Pending = 0,
    /// Fully registered, traffic can flow
    Confirmed = 1,
}

/// eBPF map entry for a registration
#[repr(C)]
#[derive(Debug, Clone, Copy)]
pub struct Registration {
    /// Current state
    pub state: u8,
    pub _pad1: [u8; 3],
    /// Client IPv4 address
    pub client_ip: u32,
    /// Client UDP port
    pub client_port: u16,
    pub _pad2: [u8; 2],
    /// Token bucket: remaining bytes
    pub tokens: u64,
    /// Last refill timestamp (ns)
    pub last_refill: u64,
    /// Registration expiry (ns)
    pub expiry: u64,
    /// Challenge nonce (for pending registrations)
    pub nonce: [u8; 32],
    /// Client public key
    pub pubkey: [u8; 32],
}

#[cfg(test)]
mod tests {
    use super::*;
    use ed25519_dalek::SigningKey;
    use rand::rngs::OsRng;

    #[test]
    fn test_register_verify() {
        let signing_key = SigningKey::generate(&mut OsRng);
        let timestamp = 1234567890u64;

        let msg = RegisterMessage::new(5000, &signing_key, timestamp);
        let pubkey = msg.verify().expect("verification should succeed");

        assert_eq!(pubkey, signing_key.verifying_key());
    }

    #[test]
    fn test_challenge_response() {
        let signing_key = SigningKey::generate(&mut OsRng);
        let pubkey = signing_key.verifying_key();

        let challenge = ChallengeMessage::new(5000);
        let response = ResponseMessage::new(challenge.nonce, 5000, &signing_key);

        response.verify(&pubkey, &challenge.nonce).expect("should verify");
    }

    #[test]
    fn test_challenge_response_wrong_nonce() {
        let signing_key = SigningKey::generate(&mut OsRng);
        let pubkey = signing_key.verifying_key();

        let challenge = ChallengeMessage::new(5000);
        let response = ResponseMessage::new(challenge.nonce, 5000, &signing_key);

        let wrong_nonce = [0u8; 32];
        let result = response.verify(&pubkey, &wrong_nonce);

        assert!(matches!(result, Err(ProtocolError::ChallengeMismatch)));
    }
}
