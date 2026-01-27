//! Freehold Common - Shared structures between server userspace and eBPF kernel
//!
//! All types here must be `repr(C)` with stable, predictable layouts.

#![cfg_attr(not(feature = "userspace"), no_std)]

/// Registration entry stored in eBPF map
///
/// This is the data contract between freehold-server and freehold-ebpf.
/// Any changes here require updating both sides.
#[repr(C)]
#[derive(Clone, Copy, Debug, Default)]
pub struct Registration {
    /// Token bucket - remaining byte budget
    pub tokens: u64,
    /// Last refill timestamp (nanoseconds, CLOCK_MONOTONIC)
    pub last_refill: u64,
    /// Destination IP for forwarding (network byte order)
    pub home_ip: u32,
    /// Destination port for forwarding (host byte order)
    pub home_port: u16,
    /// Padding for alignment
    pub _pad1: u16,
    /// Registration expiry (nanoseconds, CLOCK_MONOTONIC)
    pub expiry: u64,
}

impl Registration {
    pub const SIZE: usize = core::mem::size_of::<Self>();
}

#[cfg(feature = "userspace")]
unsafe impl aya::Pod for Registration {}

/// Event types emitted by XDP program - must match main.bpf.c
#[repr(u8)]
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum EventType {
    DropRateLimit = 1,
    DropExpired = 2,
    DropNoReg = 3,
    Forward = 4,
}

impl EventType {
    pub fn from_u8(v: u8) -> Option<Self> {
        match v {
            1 => Some(Self::DropRateLimit),
            2 => Some(Self::DropExpired),
            3 => Some(Self::DropNoReg),
            4 => Some(Self::Forward),
            _ => None,
        }
    }
}

/// Event sent from XDP to userspace via perf buffer
///
/// Must match struct event in main.bpf.c
#[repr(C)]
#[derive(Clone, Copy, Debug, Default)]
pub struct XdpEvent {
    pub src_ip: u32,
    pub dst_ip: u32,
    pub src_port: u16,
    pub dst_port: u16,
    pub pkt_len: u32,
    pub event_type: u8,
    pub _pad: [u8; 3],
}

impl XdpEvent {
    pub const SIZE: usize = core::mem::size_of::<Self>();

    pub fn event_type(&self) -> Option<EventType> {
        EventType::from_u8(self.event_type)
    }
}

#[cfg(feature = "userspace")]
unsafe impl aya::Pod for XdpEvent {}

/// Rate limiting constants - must match eBPF
pub mod rate_limit {
    /// Refill rate: 1 byte per nanosecond ≈ 8 Gbps
    pub const REFILL_PER_NS: u64 = 1;
    /// Maximum burst size: 10 MB
    pub const MAX_BURST: u64 = 10_485_760;
}

/// eBPF map names
pub mod maps {
    pub const REGISTRATIONS: &str = "registrations";
    pub const CONTROL_PORT: &str = "control_port";
    pub const EVENTS: &str = "events";
}

/// XDP program name
pub const XDP_PROGRAM: &str = "freehold_ingress";

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn registration_size() {
        assert_eq!(Registration::SIZE, 32);
    }

    #[test]
    fn registration_alignment() {
        assert_eq!(core::mem::align_of::<Registration>(), 8);
    }

    #[test]
    fn event_size() {
        // 4 + 4 + 2 + 2 + 4 + 1 + 3 = 20 bytes
        assert_eq!(XdpEvent::SIZE, 20);
    }
}
