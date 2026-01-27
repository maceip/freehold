// SPDX-License-Identifier: GPL-2.0
//
// Specular XDP Reflector v2
//
// Fast-path UDP reflection for confirmed registrations.
// Unregistered traffic passes to userspace for the registration handshake.

#include <linux/bpf.h>
#include <linux/if_ether.h>
#include <linux/ip.h>
#include <linux/udp.h>
#include <linux/in.h>
#include <linux/types.h>
#include <bpf/bpf_helpers.h>
#include <bpf/bpf_endian.h>

// --- Constants ---

#define REFILL_PER_NS 125       // 125 bytes/ns = 1 Gbps
#define MAX_BURST 10485760      // 10 MB burst
#define CONTROL_PORT 7433       // Registration protocol port

// Registration states
#define STATE_PENDING   0
#define STATE_CONFIRMED 1

// --- Data Structures ---

// Registration entry (must match common/src/lib.rs Registration)
struct registration {
    __u8  state;
    __u8  _pad1[3];
    __u32 client_ip;        // Where to reflect traffic
    __u16 client_port;
    __u8  _pad2[2];
    __u64 tokens;           // Token bucket
    __u64 last_refill;      // Timestamp (ns)
    __u64 expiry;           // Registration expiry (ns)
    __u8  nonce[32];        // Challenge nonce (pending only)
    __u8  pubkey[32];       // Client public key
};

// --- Maps ---

// Main registration table: port -> registration
struct {
    __uint(type, BPF_MAP_TYPE_HASH);
    __uint(max_entries, 65536);
    __type(key, __u16);
    __type(value, struct registration);
} registrations SEC(".maps");

// Quota tracking: client_ip -> port_count
struct {
    __uint(type, BPF_MAP_TYPE_HASH);
    __uint(max_entries, 1000000);
    __type(key, __u32);
    __type(value, __u32);
} quota_map SEC(".maps");

// Stats
struct {
    __uint(type, BPF_MAP_TYPE_PERCPU_ARRAY);
    __uint(max_entries, 4);
    __type(key, __u32);
    __type(value, __u64);
} stats SEC(".maps");

#define STAT_REFLECTED  0
#define STAT_PASSED     1
#define STAT_DROPPED    2
#define STAT_RATE_LIMITED 3

// --- Helpers ---

static __always_inline void update_stat(__u32 idx)
{
    __u64 *val = bpf_map_lookup_elem(&stats, &idx);
    if (val)
        __sync_fetch_and_add(val, 1);
}

static __always_inline __u16 csum_fold(__u32 csum)
{
    csum = (csum & 0xffff) + (csum >> 16);
    csum = (csum & 0xffff) + (csum >> 16);
    return (__u16)~csum;
}

static __always_inline void update_ip_csum(struct iphdr *ip, __u32 old_addr, __u32 new_addr)
{
    __u32 csum = ~(((__u32)ip->check) & 0xffff);
    csum += ~(old_addr & 0xffff) & 0xffff;
    csum += ~(old_addr >> 16) & 0xffff;
    csum += new_addr & 0xffff;
    csum += new_addr >> 16;
    ip->check = csum_fold(csum);
}

// --- Main XDP Program ---

SEC("xdp")
int specular_ingress(struct xdp_md *ctx)
{
    void *data_end = (void *)(long)ctx->data_end;
    void *data = (void *)(long)ctx->data;

    // Parse Ethernet
    struct ethhdr *eth = data;
    if ((void *)(eth + 1) > data_end)
        return XDP_PASS;
    if (eth->h_proto != bpf_htons(ETH_P_IP))
        return XDP_PASS;

    // Parse IP
    struct iphdr *ip = (void *)(eth + 1);
    if ((void *)(ip + 1) > data_end)
        return XDP_PASS;
    if (ip->protocol != IPPROTO_UDP)
        return XDP_PASS;

    // Parse UDP
    struct udphdr *udp = (void *)ip + (ip->ihl * 4);
    if ((void *)(udp + 1) > data_end)
        return XDP_PASS;

    __u16 dest_port = bpf_ntohs(udp->dest);
    __u32 src_ip = ip->saddr;
    __u16 src_port = bpf_ntohs(udp->source);

    // Control port traffic always goes to userspace
    if (dest_port == CONTROL_PORT) {
        update_stat(STAT_PASSED);
        return XDP_PASS;
    }

    // Lookup registration
    struct registration *reg = bpf_map_lookup_elem(&registrations, &dest_port);

    if (!reg) {
        // No registration - pass to userspace
        // Userspace can decide to start registration or drop
        update_stat(STAT_PASSED);
        return XDP_PASS;
    }

    // Check registration state
    if (reg->state != STATE_CONFIRMED) {
        // Pending registration - pass to userspace for challenge handling
        update_stat(STAT_PASSED);
        return XDP_PASS;
    }

    // Check expiry
    __u64 now = bpf_ktime_get_ns();
    if (now > reg->expiry) {
        // Registration expired - pass to userspace
        update_stat(STAT_PASSED);
        return XDP_PASS;
    }

    // Rate limiting with token bucket
    __u64 elapsed = now - reg->last_refill;
    if (elapsed > 0) {
        reg->tokens += elapsed * REFILL_PER_NS;
        if (reg->tokens > MAX_BURST)
            reg->tokens = MAX_BURST;
        reg->last_refill = now;
    }

    __u64 pkt_len = data_end - data;
    if (reg->tokens < pkt_len) {
        // Rate limited - drop
        update_stat(STAT_RATE_LIMITED);
        return XDP_DROP;
    }
    reg->tokens -= pkt_len;

    // --- Reflect the packet ---

    // Swap MAC addresses
    __u8 tmp_mac[ETH_ALEN];
    __builtin_memcpy(tmp_mac, eth->h_dest, ETH_ALEN);
    __builtin_memcpy(eth->h_dest, eth->h_source, ETH_ALEN);
    __builtin_memcpy(eth->h_source, tmp_mac, ETH_ALEN);

    // Rewrite destination IP to client
    __u32 old_daddr = ip->daddr;
    ip->daddr = bpf_htonl(reg->client_ip);
    update_ip_csum(ip, old_daddr, bpf_htonl(reg->client_ip));

    // Rewrite destination port
    udp->dest = bpf_htons(reg->client_port);

    // Zero UDP checksum (let NIC offload handle it, or recalc in software)
    udp->check = 0;

    update_stat(STAT_REFLECTED);
    return XDP_TX;
}

// --- Egress program for responses (optional) ---

SEC("xdp")
int specular_egress(struct xdp_md *ctx)
{
    // Can be used for outgoing challenge packets if needed
    return XDP_PASS;
}

char _license[] SEC("license") = "GPL";
