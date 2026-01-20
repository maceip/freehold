#include <linux/bpf.h>
#include <linux/if_ether.h>
#include <linux/ip.h>
#include <linux/udp.h>
#include <linux/in.h>
#include <linux/types.h>
#include <bpf/bpf_helpers.h>
#include <bpf/bpf_endian.h>

#define MAX_NEIGHBORS 8
#define REFILL_PER_NS 1      // 1 byte per ns = ~8Gbps
#define MAX_BURST 10485760   // 10MB burst window
#define QUOTA_LIMIT 3        // Max ports per Source IP

// --- Data Structures ---

struct neighbor_list {
    __u32 count;
    __u32 ipv4_addrs[MAX_NEIGHBORS];
};

struct user_mapping {
    // Traffic Control
    __u64 tokens;       // Remaining byte budget
    __u64 last_refill;  // Nanoseconds timestamp

    // Registration / Owner Info
    __u32 home_ip;      // Where to forward traffic
    __u16 home_port;    // Destination port at home
    __u32 owner_ip;     // The ISP IP that registered this
    __u64 expiry;       // Timestamp for cleanup (optional logic)
};

// --- Maps ---

// Global config map
struct {
    __uint(type, BPF_MAP_TYPE_ARRAY);
    __uint(max_entries, 1);
    __type(key, __u32);
    __type(value, struct neighbor_list);
} neighbor_map SEC(".maps");

// Main Registration Table
struct {
    __uint(type, BPF_MAP_TYPE_HASH);
    __uint(max_entries, 65536);
    __type(key, __u16); // Listening Port (on this server)
    __type(value, struct user_mapping);
} registrations SEC(".maps");

// Quota Tracking (Source IP -> Count)
struct {
    __uint(type, BPF_MAP_TYPE_HASH);
    __uint(max_entries, 1000000);
    __type(key, __u32);
    __type(value, __u32);
} ip_quota_map SEC(".maps");


// --- Logic ---

SEC("xdp")
int specular_ingress(struct xdp_md *ctx) {
    void *data_end = (void *)(long)ctx->data_end;
    void *data = (void *)(long)ctx->data;

    // 1. Parse Ethernet
    struct ethhdr *eth = data;
    if ((void *)(eth + 1) > data_end) return XDP_PASS;
    if (eth->h_proto != bpf_htons(ETH_P_IP)) return XDP_PASS;

    // 2. Parse IP
    struct iphdr *ip = (void *)(eth + 1);
    if ((void *)(ip + 1) > data_end) return XDP_PASS;
    if (ip->protocol != IPPROTO_UDP) return XDP_PASS;

    // 3. Parse UDP
    struct udphdr *udp = (void *)(ip + 1);
    if ((void *)(udp + 1) > data_end) return XDP_PASS;

    __u16 dest_port = bpf_ntohs(udp->dest);
    __u32 src_ip = ip->saddr;

    // 4. Lookup Registration
    struct user_mapping *user = bpf_map_lookup_elem(&registrations, &dest_port);

    // --- Path A: Existing User (Specular Relay Logic) ---
    if (user) {
        __u64 now = bpf_ktime_get_ns();
        __u64 elapsed = now - user->last_refill;

        // Refill tokens
        // Check for overflow/large elapsed times to avoid wrapping
        if (elapsed > 0) {
             user->tokens += elapsed * REFILL_PER_NS;
             if (user->tokens > MAX_BURST) user->tokens = MAX_BURST;
             user->last_refill = now;
        }

        __u64 len = data_end - data;
        if (user->tokens < len) {
            // Hard throttle: drop if budget exceeded
            return XDP_DROP;
        }

        // Deduct cost
        user->tokens -= len;

        // Rewrite Headers (Reflector)
        // We swap the Destination IP/Port to the "Home" values
        ip->daddr = user->home_ip;
        udp->dest = bpf_htons(user->home_port);

        // Recalculate checksums (Simplification: assuming Checksum Offload or zeroing UDP csum)
        udp->check = 0;
        ip->check = 0; // Kernel will often fix IP csum on XDP_TX if configured, else need explicit recalc

        // Fast-path TX
        return XDP_TX;
    }

    // --- Path B: New User (Reflector Registration Logic) ---
    // If no registration exists, we treat this as a registration attempt.

    // Check Quota
    __u32 *count = bpf_map_lookup_elem(&ip_quota_map, &src_ip);

    if (count && *count >= QUOTA_LIMIT) {
        return XDP_DROP; // Quota exceeded
    }

    // Initialize new mapping
    struct user_mapping new_user = {0};
    new_user.home_ip = ip->saddr;       // Reflect back to sender
    new_user.home_port = bpf_ntohs(udp->source);
    new_user.owner_ip = ip->saddr;
    new_user.tokens = MAX_BURST;        // Start with full burst
    new_user.last_refill = bpf_ktime_get_ns();
    new_user.expiry = new_user.last_refill + 3600000000000ULL; // 1 hour (example)

    // Save Registration
    if (bpf_map_update_elem(&registrations, &dest_port, &new_user, BPF_ANY) == 0) {
        // Increment Quota
        __u32 new_count = count ? (*count + 1) : 1;
        bpf_map_update_elem(&ip_quota_map, &src_ip, &new_count, BPF_ANY);
    }

    // Drop the registration packet (or pass it if you want the app to see it)
    return XDP_DROP;
}

char _license[] SEC("license") = "GPL";
