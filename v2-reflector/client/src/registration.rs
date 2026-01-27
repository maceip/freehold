//! Registration protocol client

use std::net::SocketAddr;
use std::time::{SystemTime, UNIX_EPOCH};

use anyhow::{Context, Result};
use ed25519_dalek::SigningKey;
use specular_common::*;
use tokio::net::UdpSocket;
use tokio::time::{timeout, Duration};
use tracing::{debug, info, warn};

const TIMEOUT: Duration = Duration::from_secs(5);
const MAX_RETRIES: u32 = 3;

pub struct RegistrationClient {
    relay_addr: SocketAddr,
    signing_key: SigningKey,
    socket: Option<UdpSocket>,
    sequence: u32,
}

impl RegistrationClient {
    pub fn new(relay_addr: SocketAddr, signing_key: SigningKey) -> Self {
        Self {
            relay_addr,
            signing_key,
            socket: None,
            sequence: 0,
        }
    }

    async fn ensure_socket(&mut self) -> Result<()> {
        if self.socket.is_none() {
            let socket = UdpSocket::bind("0.0.0.0:0").await?;
            socket.connect(self.relay_addr).await?;
            self.socket = Some(socket);
        }
        Ok(())
    }

    fn socket(&self) -> &UdpSocket {
        self.socket.as_ref().expect("socket not initialized")
    }

    fn next_sequence(&mut self) -> u32 {
        self.sequence = self.sequence.wrapping_add(1);
        self.sequence
    }

    pub async fn register(&mut self, requested_port: u16) -> Result<u16> {
        self.ensure_socket().await?;

        for attempt in 1..=MAX_RETRIES {
            info!("Registration attempt {}/{}", attempt, MAX_RETRIES);

            let seq = self.next_sequence();
            let timestamp = SystemTime::now()
                .duration_since(UNIX_EPOCH)
                .unwrap()
                .as_secs();

            // Send REGISTER
            let register_msg = RegisterMessage::new(requested_port, &self.signing_key, timestamp);
            let payload = bincode::serialize(&register_msg)?;
            let header = Header::new(MessageType::Register, payload.len() as u16, seq);
            let header_bytes = bincode::serialize(&header)?;

            let mut packet = header_bytes;
            packet.extend_from_slice(&payload);

            self.socket().send(&packet).await?;
            debug!("Sent REGISTER for port {}", requested_port);

            // Wait for CHALLENGE
            let challenge = match self.recv_challenge().await {
                Ok(c) => c,
                Err(e) => {
                    warn!("Failed to receive challenge: {}", e);
                    continue;
                }
            };

            info!("Received CHALLENGE for port {}", challenge.port);

            // Send RESPONSE
            let response_msg = ResponseMessage::new(
                challenge.nonce,
                challenge.port,
                &self.signing_key,
            );
            let payload = bincode::serialize(&response_msg)?;
            let header = Header::new(MessageType::Response, payload.len() as u16, seq);
            let header_bytes = bincode::serialize(&header)?;

            let mut packet = header_bytes;
            packet.extend_from_slice(&payload);

            self.socket().send(&packet).await?;
            debug!("Sent RESPONSE");

            // Wait for ACK
            match self.recv_ack().await {
                Ok(ack) => {
                    info!("Registration confirmed! Port: {}, TTL: {}s", ack.port, ack.ttl);
                    return Ok(ack.port);
                }
                Err(e) => {
                    warn!("Failed to receive ACK: {}", e);
                    continue;
                }
            }
        }

        anyhow::bail!("Registration failed after {} attempts", MAX_RETRIES)
    }

    async fn recv_challenge(&self) -> Result<ChallengeMessage> {
        let socket = self.socket();
        let mut buf = vec![0u8; 2048];

        let len = timeout(TIMEOUT, socket.recv(&mut buf))
            .await
            .context("Timeout waiting for challenge")?
            .context("Failed to receive")?;

        let data = &buf[..len];

        // Parse header
        if data.len() < 12 {
            anyhow::bail!("Packet too short");
        }

        if &data[0..4] != &MAGIC {
            anyhow::bail!("Invalid magic");
        }

        let msg_type = MessageType::try_from(data[5])?;

        match msg_type {
            MessageType::Challenge => {
                let challenge: ChallengeMessage = bincode::deserialize(&data[12..])?;
                Ok(challenge)
            }
            MessageType::ErrorResponse => {
                let error: ErrorMessage = bincode::deserialize(&data[12..])?;
                anyhow::bail!("Relay error {}: {}", error.code, error.message)
            }
            _ => anyhow::bail!("Unexpected message type: {:?}", msg_type),
        }
    }

    async fn recv_ack(&self) -> Result<AckMessage> {
        let socket = self.socket();
        let mut buf = vec![0u8; 2048];

        let len = timeout(TIMEOUT, socket.recv(&mut buf))
            .await
            .context("Timeout waiting for ACK")?
            .context("Failed to receive")?;

        let data = &buf[..len];

        if data.len() < 12 {
            anyhow::bail!("Packet too short");
        }

        if &data[0..4] != &MAGIC {
            anyhow::bail!("Invalid magic");
        }

        let msg_type = MessageType::try_from(data[5])?;

        match msg_type {
            MessageType::Ack => {
                let ack: AckMessage = bincode::deserialize(&data[12..])?;
                Ok(ack)
            }
            MessageType::ErrorResponse => {
                let error: ErrorMessage = bincode::deserialize(&data[12..])?;
                anyhow::bail!("Relay error {}: {}", error.code, error.message)
            }
            _ => anyhow::bail!("Unexpected message type: {:?}", msg_type),
        }
    }

    pub async fn heartbeat(&mut self, port: u16) -> Result<u32> {
        self.ensure_socket().await?;
        let seq = self.next_sequence();

        let timestamp = SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .unwrap()
            .as_secs();

        let hb_msg = HeartbeatMessage::new(port, &self.signing_key, timestamp);
        let payload = bincode::serialize(&hb_msg)?;
        let header = Header::new(MessageType::Heartbeat, payload.len() as u16, seq);
        let header_bytes = bincode::serialize(&header)?;

        let mut packet = header_bytes;
        packet.extend_from_slice(&payload);

        self.socket().send(&packet).await?;

        // Wait for HeartbeatAck
        let socket = self.socket();
        let mut buf = vec![0u8; 2048];
        let len = timeout(TIMEOUT, socket.recv(&mut buf))
            .await
            .context("Timeout waiting for heartbeat ACK")?
            .context("Failed to receive")?;

        let data = &buf[..len];

        if data.len() < 12 {
            anyhow::bail!("Packet too short");
        }

        let msg_type = MessageType::try_from(data[5])?;

        match msg_type {
            MessageType::HeartbeatAck => {
                let ack: HeartbeatAckMessage = bincode::deserialize(&data[12..])?;
                Ok(ack.ttl)
            }
            MessageType::ErrorResponse => {
                let error: ErrorMessage = bincode::deserialize(&data[12..])?;
                anyhow::bail!("Relay error {}: {}", error.code, error.message)
            }
            _ => anyhow::bail!("Unexpected message type: {:?}", msg_type),
        }
    }
}
