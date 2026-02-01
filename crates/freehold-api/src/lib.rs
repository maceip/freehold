//! Freehold API - Network protocol between client and server
//!
//! This defines the wire format for registration, heartbeat, and neighbor discovery.

use byteorder::{BigEndian, ByteOrder};
use std::net::Ipv4Addr;

/// Protocol magic byte - 'F' for Freehold
pub const MAGIC: u8 = 0x46;

/// Cookie size in bytes (truncated HMAC-SHA256)
pub const COOKIE_SIZE: usize = 16;

/// Maximum neighbors in a NEIGHBORS response
pub const MAX_NEIGHBORS: usize = 8;

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

    /// Minimum interval between REGISTER retries when disconnected
    pub const REGISTER_RETRY_INTERVAL: Duration = Duration::from_millis(100);
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
#[derive(Debug, Clone, PartialEq, Eq)]
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
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    // ==================== Message Type Tests ====================

    #[test]
    fn message_type_valid_conversions() {
        assert_eq!(MessageType::try_from(0x01).unwrap(), MessageType::Register);
        assert_eq!(MessageType::try_from(0x02).unwrap(), MessageType::Challenge);
        assert_eq!(MessageType::try_from(0x03).unwrap(), MessageType::Confirm);
        assert_eq!(MessageType::try_from(0x04).unwrap(), MessageType::Heartbeat);
        assert_eq!(MessageType::try_from(0x05).unwrap(), MessageType::Neighbors);
        assert_eq!(MessageType::try_from(0xFF).unwrap(), MessageType::Error);
    }

    #[test]
    fn message_type_invalid_conversions() {
        // Test all invalid values
        for i in [0x00, 0x06, 0x10, 0x80, 0xFE] {
            assert!(matches!(
                MessageType::try_from(i),
                Err(ProtocolError::InvalidMessageType(v)) if v == i
            ));
        }
    }

    // ==================== Roundtrip Tests ====================

    #[test]
    fn roundtrip_register() {
        let msg = Message::Register { port: 443 };
        let bytes = msg.to_bytes();
        let parsed = Message::parse(&bytes).unwrap();
        assert!(matches!(parsed, Message::Register { port: 443 }));
    }

    #[test]
    fn roundtrip_register_edge_ports() {
        // Test port boundaries
        for port in [0, 1, 80, 443, 8080, 65534, 65535] {
            let msg = Message::Register { port };
            let bytes = msg.to_bytes();
            let parsed = Message::parse(&bytes).unwrap();
            assert!(matches!(parsed, Message::Register { port: p } if p == port));
        }
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
    fn roundtrip_confirm() {
        let cookie = [0xAB; COOKIE_SIZE];
        let msg = Message::Confirm { port: 9000, cookie };
        let bytes = msg.to_bytes();
        let parsed = Message::parse(&bytes).unwrap();
        assert!(matches!(parsed, Message::Confirm { port: 9000, cookie: c } if c == cookie));
    }

    #[test]
    fn roundtrip_heartbeat() {
        let msg = Message::Heartbeat { port: 12345 };
        let bytes = msg.to_bytes();
        let parsed = Message::parse(&bytes).unwrap();
        assert!(matches!(parsed, Message::Heartbeat { port: 12345 }));
    }

    #[test]
    fn roundtrip_error() {
        let msg = Message::Error { port: 443 };
        let bytes = msg.to_bytes();
        let parsed = Message::parse(&bytes).unwrap();
        assert!(matches!(parsed, Message::Error { port: 443 }));
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
    fn roundtrip_neighbors_empty() {
        let msg = Message::Neighbors { addrs: vec![] };
        let bytes = msg.to_bytes();
        let parsed = Message::parse(&bytes).unwrap();
        assert!(matches!(parsed, Message::Neighbors { addrs } if addrs.is_empty()));
    }

    #[test]
    fn roundtrip_neighbors_max() {
        let addrs: Vec<Ipv4Addr> = (0..MAX_NEIGHBORS as u8)
            .map(|i| Ipv4Addr::new(10, 0, 0, i))
            .collect();
        let msg = Message::Neighbors {
            addrs: addrs.clone(),
        };
        let bytes = msg.to_bytes();
        let parsed = Message::parse(&bytes).unwrap();
        assert!(matches!(parsed, Message::Neighbors { addrs: a } if a == addrs));
    }

    #[test]
    fn neighbors_truncates_to_max() {
        // Create more than MAX_NEIGHBORS addresses
        let addrs: Vec<Ipv4Addr> = (0..20).map(|i| Ipv4Addr::new(10, 0, 0, i)).collect();
        let msg = Message::Neighbors { addrs };
        let bytes = msg.to_bytes();
        let parsed = Message::parse(&bytes).unwrap();
        if let Message::Neighbors { addrs } = parsed {
            assert_eq!(addrs.len(), MAX_NEIGHBORS);
        } else {
            panic!("Expected Neighbors message");
        }
    }

    // ==================== Wire Format Tests ====================

    #[test]
    fn wire_format_magic_byte() {
        let msg = Message::Register { port: 443 };
        let bytes = msg.to_bytes();
        assert_eq!(bytes[0], MAGIC);
        assert_eq!(bytes[0], 0x46); // 'F'
    }

    #[test]
    fn wire_format_message_types() {
        assert_eq!(Message::Register { port: 0 }.to_bytes()[1], 0x01);
        assert_eq!(
            Message::Challenge {
                port: 0,
                cookie: [0; COOKIE_SIZE]
            }
            .to_bytes()[1],
            0x02
        );
        assert_eq!(
            Message::Confirm {
                port: 0,
                cookie: [0; COOKIE_SIZE]
            }
            .to_bytes()[1],
            0x03
        );
        assert_eq!(Message::Heartbeat { port: 0 }.to_bytes()[1], 0x04);
        assert_eq!(Message::Neighbors { addrs: vec![] }.to_bytes()[1], 0x05);
        assert_eq!(Message::Error { port: 0 }.to_bytes()[1], 0xFF);
    }

    #[test]
    fn wire_format_port_big_endian() {
        let msg = Message::Register { port: 0x1234 };
        let bytes = msg.to_bytes();
        assert_eq!(bytes[2], 0x12); // High byte first
        assert_eq!(bytes[3], 0x34); // Low byte second
    }

    #[test]
    fn wire_format_message_lengths() {
        assert_eq!(Message::Register { port: 0 }.to_bytes().len(), 4);
        assert_eq!(
            Message::Challenge {
                port: 0,
                cookie: [0; COOKIE_SIZE]
            }
            .to_bytes()
            .len(),
            4 + COOKIE_SIZE
        );
        assert_eq!(
            Message::Confirm {
                port: 0,
                cookie: [0; COOKIE_SIZE]
            }
            .to_bytes()
            .len(),
            4 + COOKIE_SIZE
        );
        assert_eq!(Message::Heartbeat { port: 0 }.to_bytes().len(), 4);
        assert_eq!(Message::Error { port: 0 }.to_bytes().len(), 4);
        assert_eq!(Message::Neighbors { addrs: vec![] }.to_bytes().len(), 3);

        // Neighbors with 2 IPs = 3 + 2*4 = 11
        let addrs = vec![Ipv4Addr::LOCALHOST, Ipv4Addr::LOCALHOST];
        assert_eq!(Message::Neighbors { addrs }.to_bytes().len(), 11);
    }

    // ==================== Parse Error Tests ====================

    #[test]
    fn parse_error_empty() {
        let result = Message::parse(&[]);
        assert!(matches!(
            result,
            Err(ProtocolError::TooShort {
                expected: 2,
                actual: 0
            })
        ));
    }

    #[test]
    fn parse_error_too_short_header() {
        let result = Message::parse(&[MAGIC]);
        assert!(matches!(
            result,
            Err(ProtocolError::TooShort {
                expected: 2,
                actual: 1
            })
        ));
    }

    #[test]
    fn parse_error_invalid_magic() {
        let result = Message::parse(&[0x00, 0x01, 0x00, 0x50]);
        assert!(matches!(result, Err(ProtocolError::InvalidMagic(0x00))));

        let result = Message::parse(&[0xFF, 0x01, 0x00, 0x50]);
        assert!(matches!(result, Err(ProtocolError::InvalidMagic(0xFF))));
    }

    #[test]
    fn parse_error_invalid_message_type() {
        let result = Message::parse(&[MAGIC, 0x00, 0x00, 0x50]);
        assert!(matches!(
            result,
            Err(ProtocolError::InvalidMessageType(0x00))
        ));

        let result = Message::parse(&[MAGIC, 0x99, 0x00, 0x50]);
        assert!(matches!(
            result,
            Err(ProtocolError::InvalidMessageType(0x99))
        ));
    }

    #[test]
    fn parse_error_truncated_register() {
        let result = Message::parse(&[MAGIC, 0x01, 0x00]); // Missing last port byte
        assert!(matches!(
            result,
            Err(ProtocolError::TooShort {
                expected: 4,
                actual: 3
            })
        ));
    }

    #[test]
    fn parse_error_truncated_challenge() {
        // Challenge needs 4 + 16 = 20 bytes
        let result = Message::parse(&[MAGIC, 0x02, 0x00, 0x50, 0x00, 0x00, 0x00, 0x00]);
        assert!(matches!(
            result,
            Err(ProtocolError::TooShort {
                expected: 20,
                actual: 8
            })
        ));
    }

    #[test]
    fn parse_error_truncated_neighbors() {
        // Says 2 neighbors but only provides 1
        let result = Message::parse(&[MAGIC, 0x05, 0x02, 10, 0, 0, 1]);
        assert!(matches!(
            result,
            Err(ProtocolError::TooShort {
                expected: 11,
                actual: 7
            })
        ));
    }

    // ==================== Cookie Tests ====================

    #[test]
    fn cookie_preserves_exact_bytes() {
        let cookie: [u8; COOKIE_SIZE] = [
            0x01, 0x23, 0x45, 0x67, 0x89, 0xAB, 0xCD, 0xEF, 0xFE, 0xDC, 0xBA, 0x98, 0x76, 0x54,
            0x32, 0x10,
        ];
        let msg = Message::Challenge { port: 8080, cookie };
        let bytes = msg.to_bytes();

        // Cookie should be at bytes 4..20
        assert_eq!(&bytes[4..20], &cookie);

        let parsed = Message::parse(&bytes).unwrap();
        if let Message::Challenge {
            port: _,
            cookie: parsed_cookie,
        } = parsed
        {
            assert_eq!(parsed_cookie, cookie);
        } else {
            panic!("Expected Challenge message");
        }
    }

    #[test]
    fn cookie_size_constant() {
        assert_eq!(COOKIE_SIZE, 16);
    }

    // ==================== Timing Constants Tests ====================

    #[test]
    fn timing_constants_relationships() {
        // Heartbeat should be less than TTL
        assert!(timing::HEARTBEAT_INTERVAL < timing::REGISTRATION_TTL);

        // Register timeout should be much less than heartbeat
        assert!(timing::REGISTER_TIMEOUT < timing::HEARTBEAT_INTERVAL);

        // Time bucket should be reasonable
        assert!(timing::TIME_BUCKET.as_secs() > 0);
        assert!(timing::TIME_BUCKET.as_secs() <= 60);
    }

    // ==================== IP Address Tests ====================

    #[test]
    fn neighbors_ip_addresses() {
        let addrs = vec![
            Ipv4Addr::new(192, 168, 1, 1),
            Ipv4Addr::new(10, 0, 0, 1),
            Ipv4Addr::new(172, 16, 0, 1),
            Ipv4Addr::LOCALHOST,
            Ipv4Addr::BROADCAST,
        ];
        let msg = Message::Neighbors {
            addrs: addrs.clone(),
        };
        let bytes = msg.to_bytes();
        let parsed = Message::parse(&bytes).unwrap();
        if let Message::Neighbors {
            addrs: parsed_addrs,
        } = parsed
        {
            assert_eq!(parsed_addrs, addrs);
        } else {
            panic!("Expected Neighbors message");
        }
    }

    // ==================== Extra Data Handling ====================

    #[test]
    fn parse_ignores_trailing_bytes() {
        // Register message with extra trailing data
        let mut bytes = Message::Register { port: 443 }.to_bytes();
        bytes.extend_from_slice(&[0xFF, 0xFF, 0xFF, 0xFF]);

        let parsed = Message::parse(&bytes).unwrap();
        assert!(matches!(parsed, Message::Register { port: 443 }));
    }
}

/// Property-based tests using proptest
#[cfg(test)]
mod proptests {
    use super::*;
    use proptest::prelude::*;

    // Strategy to generate random ports
    fn port_strategy() -> impl Strategy<Value = u16> {
        any::<u16>()
    }

    // Strategy to generate random cookies
    fn cookie_strategy() -> impl Strategy<Value = [u8; COOKIE_SIZE]> {
        prop::array::uniform16(any::<u8>())
    }

    // Strategy to generate random IPv4 addresses
    fn ipv4_strategy() -> impl Strategy<Value = Ipv4Addr> {
        (any::<u8>(), any::<u8>(), any::<u8>(), any::<u8>())
            .prop_map(|(a, b, c, d)| Ipv4Addr::new(a, b, c, d))
    }

    // Strategy to generate a list of IPv4 addresses
    fn ipv4_vec_strategy() -> impl Strategy<Value = Vec<Ipv4Addr>> {
        prop::collection::vec(ipv4_strategy(), 0..=MAX_NEIGHBORS)
    }

    proptest! {
        /// All Register messages should roundtrip correctly
        #[test]
        fn prop_roundtrip_register(port in port_strategy()) {
            let msg = Message::Register { port };
            let bytes = msg.to_bytes();
            let parsed = Message::parse(&bytes).unwrap();
            match parsed {
                Message::Register { port: p } => prop_assert_eq!(p, port),
                _ => prop_assert!(false, "Wrong message type"),
            }
        }

        /// All Challenge messages should roundtrip correctly
        #[test]
        fn prop_roundtrip_challenge(port in port_strategy(), cookie in cookie_strategy()) {
            let msg = Message::Challenge { port, cookie };
            let bytes = msg.to_bytes();
            let parsed = Message::parse(&bytes).unwrap();
            match parsed {
                Message::Challenge { port: p, cookie: c } => {
                    prop_assert_eq!(p, port);
                    prop_assert_eq!(c, cookie);
                }
                _ => prop_assert!(false, "Wrong message type"),
            }
        }

        /// All Confirm messages should roundtrip correctly
        #[test]
        fn prop_roundtrip_confirm(port in port_strategy(), cookie in cookie_strategy()) {
            let msg = Message::Confirm { port, cookie };
            let bytes = msg.to_bytes();
            let parsed = Message::parse(&bytes).unwrap();
            match parsed {
                Message::Confirm { port: p, cookie: c } => {
                    prop_assert_eq!(p, port);
                    prop_assert_eq!(c, cookie);
                }
                _ => prop_assert!(false, "Wrong message type"),
            }
        }

        /// All Heartbeat messages should roundtrip correctly
        #[test]
        fn prop_roundtrip_heartbeat(port in port_strategy()) {
            let msg = Message::Heartbeat { port };
            let bytes = msg.to_bytes();
            let parsed = Message::parse(&bytes).unwrap();
            match parsed {
                Message::Heartbeat { port: p } => prop_assert_eq!(p, port),
                _ => prop_assert!(false, "Wrong message type"),
            }
        }

        /// All Error messages should roundtrip correctly
        #[test]
        fn prop_roundtrip_error(port in port_strategy()) {
            let msg = Message::Error { port };
            let bytes = msg.to_bytes();
            let parsed = Message::parse(&bytes).unwrap();
            match parsed {
                Message::Error { port: p } => prop_assert_eq!(p, port),
                _ => prop_assert!(false, "Wrong message type"),
            }
        }

        /// All Neighbors messages should roundtrip correctly
        #[test]
        fn prop_roundtrip_neighbors(addrs in ipv4_vec_strategy()) {
            let msg = Message::Neighbors { addrs: addrs.clone() };
            let bytes = msg.to_bytes();
            let parsed = Message::parse(&bytes).unwrap();
            match parsed {
                Message::Neighbors { addrs: a } => prop_assert_eq!(a, addrs),
                _ => prop_assert!(false, "Wrong message type"),
            }
        }

        /// Register messages should have consistent wire format
        #[test]
        fn prop_register_wire_format(port in port_strategy()) {
            let bytes = Message::Register { port }.to_bytes();
            prop_assert_eq!(bytes.len(), 4);
            prop_assert_eq!(bytes[0], MAGIC);
            prop_assert_eq!(bytes[1], MessageType::Register as u8);
            // Port should be big-endian
            prop_assert_eq!(bytes[2], (port >> 8) as u8);
            prop_assert_eq!(bytes[3], (port & 0xFF) as u8);
        }

        /// Challenge messages should have consistent wire format
        #[test]
        fn prop_challenge_wire_format(port in port_strategy(), cookie in cookie_strategy()) {
            let bytes = Message::Challenge { port, cookie }.to_bytes();
            prop_assert_eq!(bytes.len(), 4 + COOKIE_SIZE);
            prop_assert_eq!(bytes[0], MAGIC);
            prop_assert_eq!(bytes[1], MessageType::Challenge as u8);
            prop_assert_eq!(&bytes[4..], &cookie);
        }

        /// Neighbors messages should encode count correctly
        #[test]
        fn prop_neighbors_count(addrs in ipv4_vec_strategy()) {
            let expected_count = addrs.len().min(MAX_NEIGHBORS);
            let bytes = Message::Neighbors { addrs }.to_bytes();
            prop_assert_eq!(bytes[2] as usize, expected_count);
            prop_assert_eq!(bytes.len(), 3 + expected_count * 4);
        }

        /// Invalid magic byte should always fail
        #[test]
        fn prop_invalid_magic_fails(magic in any::<u8>().prop_filter("Not MAGIC", |&m| m != MAGIC)) {
            let data = vec![magic, 0x01, 0x00, 0x50];
            let result = Message::parse(&data);
            prop_assert!(matches!(result, Err(ProtocolError::InvalidMagic(_))));
        }

        /// Invalid message types should fail
        #[test]
        fn prop_invalid_message_type_fails(
            msg_type in any::<u8>().prop_filter("Invalid type", |&t| {
                !matches!(t, 0x01 | 0x02 | 0x03 | 0x04 | 0x05 | 0xFF)
            })
        ) {
            let data = vec![MAGIC, msg_type, 0x00, 0x50];
            let result = Message::parse(&data);
            prop_assert!(matches!(result, Err(ProtocolError::InvalidMessageType(_))));
        }

        /// Truncated messages should fail with TooShort
        #[test]
        fn prop_truncated_register_fails(len in 0usize..4) {
            let full = Message::Register { port: 443 }.to_bytes();
            let truncated = &full[..len.min(full.len())];
            let result = Message::parse(truncated);
            prop_assert!(result.is_err());
        }
    }
}
