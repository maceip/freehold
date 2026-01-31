//! Freehold API - Network protocol between client and server
//!
//! This defines the wire format for registration, heartbeat, neighbor discovery,
//! and remote attestation.

use byteorder::{BigEndian, ByteOrder};
use std::net::Ipv4Addr;

/// Protocol magic byte - 'F' for Freehold
pub const MAGIC: u8 = 0x46;

/// Cookie size in bytes (truncated HMAC-SHA256)
pub const COOKIE_SIZE: usize = 16;

/// Maximum neighbors in a NEIGHBORS response
pub const MAX_NEIGHBORS: usize = 8;

/// Attestation nonce size (for freshness)
pub const ATTESTATION_NONCE_SIZE: usize = 32;

/// Maximum attestation response size (quote + collateral)
pub const MAX_ATTESTATION_SIZE: usize = 16384;

/// Protocol timing constants
pub mod timing {
    use std::time::Duration;

    /// Time bucket for cookie generation
    pub const TIME_BUCKET: Duration = Duration::from_secs(30);

    /// Registration TTL - must heartbeat within this
    pub const REGISTRATION_TTL: Duration = Duration::from_secs(60);

    /// Heartbeat interval - should be < TTL
    pub const HEARTBEAT_INTERVAL: Duration = Duration::from_secs(25);

    /// Timeout waiting for challenge response
    pub const REGISTER_TIMEOUT: Duration = Duration::from_secs(5);
}

/// Protocol quota limits
pub mod quota {
    /// Maximum ports per source IP
    pub const MAX_PORTS_PER_IP: u32 = 3;
}

/// Message types
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
#[repr(u8)]
pub enum MessageType {
    Register = 0x01,
    Challenge = 0x02,
    Confirm = 0x03,
    Heartbeat = 0x04,
    Neighbors = 0x05,
    /// Request SGX attestation quote with nonce
    AttestationRequest = 0x10,
    /// SGX attestation quote response
    AttestationResponse = 0x11,
    Error = 0xFF,
}

impl TryFrom<u8> for MessageType {
    type Error = ProtocolError;

    fn try_from(value: u8) -> Result<Self, ProtocolError> {
        match value {
            0x01 => Ok(Self::Register),
            0x02 => Ok(Self::Challenge),
            0x03 => Ok(Self::Confirm),
            0x04 => Ok(Self::Heartbeat),
            0x05 => Ok(Self::Neighbors),
            0x10 => Ok(Self::AttestationRequest),
            0x11 => Ok(Self::AttestationResponse),
            0xFF => Ok(Self::Error),
            _ => Err(ProtocolError::InvalidMessageType(value)),
        }
    }
}

/// Protocol errors
#[derive(Debug, thiserror::Error)]
pub enum ProtocolError {
    #[error("invalid magic byte: {0:#x}")]
    InvalidMagic(u8),
    #[error("invalid message type: {0:#x}")]
    InvalidMessageType(u8),
    #[error("message too short: expected {expected}, got {actual}")]
    TooShort { expected: usize, actual: usize },
    #[error("invalid cookie")]
    InvalidCookie,
}

/// Parsed protocol message
#[derive(Debug, Clone)]
pub enum Message {
    /// Client -> Server: Request to register a port
    Register { port: u16 },

    /// Server -> Client: Challenge with cookie to prove IP ownership
    Challenge {
        port: u16,
        cookie: [u8; COOKIE_SIZE],
    },

    /// Client -> Server: Echo cookie to confirm registration
    Confirm {
        port: u16,
        cookie: [u8; COOKIE_SIZE],
    },

    /// Client -> Server: Keep registration alive
    Heartbeat { port: u16 },

    /// Server -> Client: List of neighbor relay IPs
    Neighbors { addrs: Vec<Ipv4Addr> },

    /// Client -> Server: Request SGX attestation quote
    /// Nonce ensures freshness (prevents replay attacks)
    AttestationRequest { nonce: [u8; ATTESTATION_NONCE_SIZE] },

    /// Server -> Client: SGX attestation quote with collateral
    /// Quote contains MRENCLAVE and includes nonce in report_data
    AttestationResponse {
        /// DCAP ECDSA quote (contains MRENCLAVE, nonce in report_data)
        quote: Vec<u8>,
        /// Collateral for offline verification (PCK certs, TCB info)
        collateral: Vec<u8>,
    },

    /// Server -> Client: Error response
    Error { port: u16 },
}

impl Message {
    /// Parse a message from bytes
    pub fn parse(data: &[u8]) -> Result<Self, ProtocolError> {
        if data.len() < 2 {
            return Err(ProtocolError::TooShort {
                expected: 2,
                actual: data.len(),
            });
        }

        if data[0] != MAGIC {
            return Err(ProtocolError::InvalidMagic(data[0]));
        }

        let msg_type = MessageType::try_from(data[1])?;

        match msg_type {
            MessageType::Register | MessageType::Heartbeat | MessageType::Error => {
                if data.len() < 4 {
                    return Err(ProtocolError::TooShort {
                        expected: 4,
                        actual: data.len(),
                    });
                }
                let port = BigEndian::read_u16(&data[2..4]);
                Ok(match msg_type {
                    MessageType::Register => Message::Register { port },
                    MessageType::Heartbeat => Message::Heartbeat { port },
                    MessageType::Error => Message::Error { port },
                    _ => unreachable!(),
                })
            }

            MessageType::Challenge | MessageType::Confirm => {
                if data.len() < 4 + COOKIE_SIZE {
                    return Err(ProtocolError::TooShort {
                        expected: 4 + COOKIE_SIZE,
                        actual: data.len(),
                    });
                }
                let port = BigEndian::read_u16(&data[2..4]);
                let mut cookie = [0u8; COOKIE_SIZE];
                cookie.copy_from_slice(&data[4..4 + COOKIE_SIZE]);
                Ok(match msg_type {
                    MessageType::Challenge => Message::Challenge { port, cookie },
                    MessageType::Confirm => Message::Confirm { port, cookie },
                    _ => unreachable!(),
                })
            }

            MessageType::Neighbors => {
                if data.len() < 3 {
                    return Err(ProtocolError::TooShort {
                        expected: 3,
                        actual: data.len(),
                    });
                }
                let count = data[2] as usize;
                if data.len() < 3 + count * 4 {
                    return Err(ProtocolError::TooShort {
                        expected: 3 + count * 4,
                        actual: data.len(),
                    });
                }
                let addrs = (0..count)
                    .map(|i| {
                        let offset = 3 + i * 4;
                        Ipv4Addr::new(
                            data[offset],
                            data[offset + 1],
                            data[offset + 2],
                            data[offset + 3],
                        )
                    })
                    .collect();
                Ok(Message::Neighbors { addrs })
            }

            MessageType::AttestationRequest => {
                if data.len() < 2 + ATTESTATION_NONCE_SIZE {
                    return Err(ProtocolError::TooShort {
                        expected: 2 + ATTESTATION_NONCE_SIZE,
                        actual: data.len(),
                    });
                }
                let mut nonce = [0u8; ATTESTATION_NONCE_SIZE];
                nonce.copy_from_slice(&data[2..2 + ATTESTATION_NONCE_SIZE]);
                Ok(Message::AttestationRequest { nonce })
            }

            MessageType::AttestationResponse => {
                if data.len() < 6 {
                    return Err(ProtocolError::TooShort {
                        expected: 6,
                        actual: data.len(),
                    });
                }
                let quote_len = BigEndian::read_u16(&data[2..4]) as usize;
                if data.len() < 4 + quote_len + 2 {
                    return Err(ProtocolError::TooShort {
                        expected: 4 + quote_len + 2,
                        actual: data.len(),
                    });
                }
                let quote = data[4..4 + quote_len].to_vec();
                let collateral_len =
                    BigEndian::read_u16(&data[4 + quote_len..6 + quote_len]) as usize;
                if data.len() < 6 + quote_len + collateral_len {
                    return Err(ProtocolError::TooShort {
                        expected: 6 + quote_len + collateral_len,
                        actual: data.len(),
                    });
                }
                let collateral = data[6 + quote_len..6 + quote_len + collateral_len].to_vec();
                Ok(Message::AttestationResponse { quote, collateral })
            }
        }
    }

    /// Serialize message to bytes
    pub fn to_bytes(&self) -> Vec<u8> {
        match self {
            Message::Register { port } => {
                let mut buf = vec![MAGIC, MessageType::Register as u8, 0, 0];
                BigEndian::write_u16(&mut buf[2..4], *port);
                buf
            }

            Message::Challenge { port, cookie } => {
                let mut buf = vec![MAGIC, MessageType::Challenge as u8, 0, 0];
                BigEndian::write_u16(&mut buf[2..4], *port);
                buf.extend_from_slice(cookie);
                buf
            }

            Message::Confirm { port, cookie } => {
                let mut buf = vec![MAGIC, MessageType::Confirm as u8, 0, 0];
                BigEndian::write_u16(&mut buf[2..4], *port);
                buf.extend_from_slice(cookie);
                buf
            }

            Message::Heartbeat { port } => {
                let mut buf = vec![MAGIC, MessageType::Heartbeat as u8, 0, 0];
                BigEndian::write_u16(&mut buf[2..4], *port);
                buf
            }

            Message::Neighbors { addrs } => {
                let count = addrs.len().min(MAX_NEIGHBORS) as u8;
                let mut buf = vec![MAGIC, MessageType::Neighbors as u8, count];
                for addr in addrs.iter().take(count as usize) {
                    buf.extend_from_slice(&addr.octets());
                }
                buf
            }

            Message::Error { port } => {
                let mut buf = vec![MAGIC, MessageType::Error as u8, 0, 0];
                BigEndian::write_u16(&mut buf[2..4], *port);
                buf
            }

            Message::AttestationRequest { nonce } => {
                let mut buf = vec![MAGIC, MessageType::AttestationRequest as u8];
                buf.extend_from_slice(nonce);
                buf
            }

            Message::AttestationResponse { quote, collateral } => {
                let mut buf = vec![MAGIC, MessageType::AttestationResponse as u8, 0, 0];
                BigEndian::write_u16(&mut buf[2..4], quote.len() as u16);
                buf.extend_from_slice(quote);
                let collateral_offset = buf.len();
                buf.extend_from_slice(&[0, 0]);
                BigEndian::write_u16(
                    &mut buf[collateral_offset..collateral_offset + 2],
                    collateral.len() as u16,
                );
                buf.extend_from_slice(collateral);
                buf
            }
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn roundtrip_register() {
        let msg = Message::Register { port: 443 };
        let bytes = msg.to_bytes();
        let parsed = Message::parse(&bytes).unwrap();
        assert!(matches!(parsed, Message::Register { port: 443 }));
    }

    #[test]
    fn roundtrip_challenge() {
        let cookie = [1u8; COOKIE_SIZE];
        let msg = Message::Challenge { port: 8080, cookie };
        let bytes = msg.to_bytes();
        let parsed = Message::parse(&bytes).unwrap();
        assert!(matches!(parsed, Message::Challenge { port: 8080, cookie: c } if c == cookie));
    }

    #[test]
    fn roundtrip_neighbors() {
        let addrs = vec![Ipv4Addr::new(10, 0, 0, 1), Ipv4Addr::new(10, 0, 0, 2)];
        let msg = Message::Neighbors {
            addrs: addrs.clone(),
        };
        let bytes = msg.to_bytes();
        let parsed = Message::parse(&bytes).unwrap();
        assert!(matches!(parsed, Message::Neighbors { addrs: a } if a == addrs));
    }

    #[test]
    fn roundtrip_attestation_request() {
        let nonce = [0x42u8; ATTESTATION_NONCE_SIZE];
        let msg = Message::AttestationRequest { nonce };
        let bytes = msg.to_bytes();
        let parsed = Message::parse(&bytes).unwrap();
        assert!(matches!(parsed, Message::AttestationRequest { nonce: n } if n == nonce));
    }

    #[test]
    fn roundtrip_attestation_response() {
        let quote = vec![1, 2, 3, 4, 5];
        let collateral = vec![6, 7, 8, 9];
        let msg = Message::AttestationResponse {
            quote: quote.clone(),
            collateral: collateral.clone(),
        };
        let bytes = msg.to_bytes();
        let parsed = Message::parse(&bytes).unwrap();
        assert!(matches!(
            parsed,
            Message::AttestationResponse { quote: q, collateral: c }
            if q == quote && c == collateral
        ));
    }
}
