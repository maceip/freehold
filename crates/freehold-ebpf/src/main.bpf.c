// SPDX-License-Identifier: GPL-2.0
//
// Freehold XDP - Fast-path packet forwarding
//
// Data plane only: lookup, rate limit, rewrite, forward.
// Registration protocol handled by freehold-server.

#include <linux/bpf.h>
#include <linux/if_ether.h>
#include <linux/ip.h>
#include <linux/udp.h>
#include <linux/in.h>
#include <linux/types.h>
#include <bpf/bpf_helpers.h>
#include <bpf/bpf_endian.h>

// Must match freehold-common
#define REFILL_PER_NS   1
#define MAX_BURST       10485760

// Event types for perf output
#define EVENT_DROP_RATE_LIMIT  1
#define EVENT_DROP_EXPIRED     2
#define EVENT_DROP_NO_REG      3
#define EVENT_FORWARD          4

struct registration {
    __u64 tokens;
    __u64 last_refill;
    __u32 home_ip;
    __u16 home_port;
    __u16 _pad1;
    __u64 expiry;
};

// Event sent to userspace via perf buffer
struct event {
    __u32 src_ip;
    __u32 dst_ip;
    __u16 src_port;
    __u16 dst_port;
    __u32 pkt_len;
    __u8  event_type;
    __u8  _pad[3];
};

struct {
    __uint(type, BPF_MAP_TYPE_HASH);
    __uint(max_entries, 65536);
    __type(key, __u16);
    __type(value, struct registration);
} registrations SEC(".maps");

struct {
    __uint(type, BPF_MAP_TYPE_ARRAY);
    __uint(max_entries, 1);
    __type(key, __u32);
    __type(value, __u16);
} control_port SEC(".maps");

struct {
    __uint(type, BPF_MAP_TYPE_PERF_EVENT_ARRAY);
    __uint(key_size, sizeof(__u32));
    __uint(value_size, sizeof(__u32));
} events SEC(".maps");

static __always_inline __u16 csum_fold(__u32 csum) {
    csum = (csum & 0xffff) + (csum >> 16);
    csum = (csum & 0xffff) + (csum >> 16);
    return (__u16)~csum;
}

static __always_inline void update_ip_csum(struct iphdr *ip,
                                            __u32 old_addr,
                                            __u32 new_addr) {
    __u32 csum = ~(__u32)ip->check;
    csum = (csum & 0xffff) + (csum >> 16);
    csum += (~old_addr & 0xffff) + (~old_addr >> 16);
    csum += (new_addr & 0xffff) + (new_addr >> 16);
    ip->check = csum_fold(csum);
}

static __always_inline void emit_event(struct xdp_md *ctx,
                                        struct iphdr *ip,
                                        struct udphdr *udp,
                                        __u32 pkt_len,
                                        __u8 event_type) {
    struct event evt = {
        .src_ip = ip->saddr,
        .dst_ip = ip->daddr,
        .src_port = bpf_ntohs(udp->source),
        .dst_port = bpf_ntohs(udp->dest),
        .pkt_len = pkt_len,
        .event_type = event_type,
    };
    bpf_perf_event_output(ctx, &events, BPF_F_CURRENT_CPU, &evt, sizeof(evt));
}

SEC("xdp")
int freehold_ingress(struct xdp_md *ctx) {
    void *data_end = (void *)(long)ctx->data_end;
    void *data = (void *)(long)ctx->data;

    struct ethhdr *eth = data;
    if ((void *)(eth + 1) > data_end)
        return XDP_PASS;
    if (eth->h_proto != bpf_htons(ETH_P_IP))
        return XDP_PASS;

    struct iphdr *ip = (void *)(eth + 1);
    if ((void *)(ip + 1) > data_end)
        return XDP_PASS;
    if (ip->protocol != IPPROTO_UDP)
        return XDP_PASS;

    struct udphdr *udp = (void *)(ip + 1);
    if ((void *)(udp + 1) > data_end)
        return XDP_PASS;

    __u16 dest_port = bpf_ntohs(udp->dest);

    // Control port -> userspace
    __u32 zero = 0;
    __u16 *ctrl = bpf_map_lookup_elem(&control_port, &zero);
    if (ctrl && dest_port == *ctrl)
        return XDP_PASS;

    struct registration *reg = bpf_map_lookup_elem(&registrations, &dest_port);
    if (!reg) {
        // No registration - could emit event but would be noisy
        return XDP_PASS;
    }

    __u64 now = bpf_ktime_get_ns();
    __u64 pkt_len = data_end - data;

    if (now > reg->expiry) {
        emit_event(ctx, ip, udp, pkt_len, EVENT_DROP_EXPIRED);
        return XDP_PASS;
    }

    // Token bucket
    __u64 elapsed = now - reg->last_refill;
    if (elapsed > 0) {
        __u64 refill = elapsed * REFILL_PER_NS;
        reg->tokens = (reg->tokens + refill > MAX_BURST) ? MAX_BURST : reg->tokens + refill;
        reg->last_refill = now;
    }

    if (reg->tokens < pkt_len) {
        emit_event(ctx, ip, udp, pkt_len, EVENT_DROP_RATE_LIMIT);
        return XDP_DROP;
    }
    reg->tokens -= pkt_len;

    // Swap MAC addresses for XDP_TX (send back out same interface)
    __u8 tmp_mac[ETH_ALEN];
    __builtin_memcpy(tmp_mac, eth->h_dest, ETH_ALEN);
    __builtin_memcpy(eth->h_dest, eth->h_source, ETH_ALEN);
    __builtin_memcpy(eth->h_source, tmp_mac, ETH_ALEN);

    // Rewrite destination IP and port
    __u32 old_daddr = ip->daddr;
    ip->daddr = reg->home_ip;
    udp->dest = bpf_htons(reg->home_port);
    update_ip_csum(ip, old_daddr, reg->home_ip);
    udp->check = 0;

    emit_event(ctx, ip, udp, pkt_len, EVENT_FORWARD);

    return XDP_TX;
}

char _license[] SEC("license") = "GPL";
