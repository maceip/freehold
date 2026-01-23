#include <linux/bpf.h>
#include <linux/if_ether.h>
#include <linux/ip.h>
#include <linux/udp.h>
#include <linux/in.h>
#include <linux/types.h>
#include <bpf/bpf_helpers.h>
#include <bpf/bpf_endian.h>

#define MAX_NEIGHBORS 8
#define MAX_PATHS 4          // Maximum paths per user for multipath QUIC
#define REFILL_PER_NS 1      // 1 byte per ns = ~8Gbps
#define MAX_BURST 10485760   // 10MB burst window
#define QUOTA_LIMIT 3        // Max ports per Source IP

// --- Data Structures ---

struct neighbor_list {
    __u32 count;
    __u32 ipv4_addrs[MAX_NEIGHBORS];
};

// Single network path endpoint
struct path_endpoint {
    __u32 ip;           // IPv4 address
    __u16 port;         // UDP port
    __u8  active;       // 1 = active, 0 = inactive
    __u8  _pad;         // Padding for alignment
    __u64 last_seen;    // Last packet timestamp (for path liveness)
    __u64 rtt_ns;       // Estimated RTT in nanoseconds (optional, for path selection)
};

struct user_mapping {
    // Traffic Control
    __u64 tokens;       // Remaining byte budget
    __u64 last_refill;  // Nanoseconds timestamp

    // Multipath endpoints - array of paths for the user
    __u8 path_count;                      // Number of active paths (1-MAX_PATHS)
    __u8 primary_path;                    // Index of preferred path for sending
    __u8 _pad[6];                         // Padding for alignment
    struct path_endpoint paths[MAX_PATHS]; // All paths for this user

    // Registration / Owner Info
    __u32 owner_ip;     // The ISP IP that registered this (first path)
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


// --- Helper Functions ---

// Find a path index for a given source IP, or -1 if not found
static __always_inline int find_path_by_ip(struct user_mapping *user, __u32 src_ip) {
    #pragma unroll
    for (int i = 0; i < MAX_PATHS; i++) {
        if (i >= user->path_count) break;
        if (user->paths[i].ip == src_ip && user->paths[i].active) {
            return i;
        }
    }
    return -1;
}

// Get the primary (preferred) path for sending
static __always_inline struct path_endpoint *get_primary_path(struct user_mapping *user) {
    if (user->path_count == 0) return 0;

    __u8 idx = user->primary_path;
    if (idx >= MAX_PATHS || idx >= user->path_count) {
        idx = 0;
    }

    if (user->paths[idx].active) {
        return &user->paths[idx];
    }

    // Fallback: find first active path
    #pragma unroll
    for (int i = 0; i < MAX_PATHS; i++) {
        if (i >= user->path_count) break;
        if (user->paths[i].active) {
            return &user->paths[i];
        }
    }

    return 0;
}

// Add or update a path for a user
static __always_inline int add_or_update_path(struct user_mapping *user, __u32 ip, __u16 port, __u64 now) {
    // Check if path already exists
    #pragma unroll
    for (int i = 0; i < MAX_PATHS; i++) {
        if (i >= user->path_count) break;
        if (user->paths[i].ip == ip) {
            // Update existing path
            user->paths[i].port = port;
            user->paths[i].active = 1;
            user->paths[i].last_seen = now;
            return i;
        }
    }

    // Add new path if space available
    if (user->path_count < MAX_PATHS) {
        int idx = user->path_count;
        user->paths[idx].ip = ip;
        user->paths[idx].port = port;
        user->paths[idx].active = 1;
        user->paths[idx].last_seen = now;
        user->paths[idx].rtt_ns = 0;
        user->path_count++;
        return idx;
    }

    return -1; // No space for new path
}


// --- Main Logic ---

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
    __u16 src_port = bpf_ntohs(udp->source);

    // 4. Lookup Registration
    struct user_mapping *user = bpf_map_lookup_elem(&registrations, &dest_port);

    // --- Path A: Existing User (Specular Relay Logic) ---
    if (user) {
        __u64 now = bpf_ktime_get_ns();
        __u64 elapsed = now - user->last_refill;

        // Refill tokens
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

        // Check if this is a known path, update last_seen
        int path_idx = find_path_by_ip(user, src_ip);
        if (path_idx >= 0 && path_idx < MAX_PATHS) {
            user->paths[path_idx].last_seen = now;
            // Update port if changed (NAT rebinding)
            user->paths[path_idx].port = src_port;
        }

        // Get primary path for forwarding
        struct path_endpoint *primary = get_primary_path(user);
        if (!primary) {
            return XDP_DROP; // No active path
        }

        // Rewrite Headers (Reflector)
        ip->daddr = primary->ip;
        udp->dest = bpf_htons(primary->port);

        // Recalculate checksums
        udp->check = 0;
        ip->check = 0;

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

    // Initialize new mapping with first path
    struct user_mapping new_user = {0};
    new_user.tokens = MAX_BURST;
    new_user.last_refill = bpf_ktime_get_ns();
    new_user.owner_ip = src_ip;
    new_user.expiry = new_user.last_refill + 3600000000000ULL; // 1 hour

    // Set up first path
    new_user.path_count = 1;
    new_user.primary_path = 0;
    new_user.paths[0].ip = src_ip;
    new_user.paths[0].port = src_port;
    new_user.paths[0].active = 1;
    new_user.paths[0].last_seen = new_user.last_refill;
    new_user.paths[0].rtt_ns = 0;

    // Save Registration
    if (bpf_map_update_elem(&registrations, &dest_port, &new_user, BPF_ANY) == 0) {
        // Increment Quota
        __u32 new_count = count ? (*count + 1) : 1;
        bpf_map_update_elem(&ip_quota_map, &src_ip, &new_count, BPF_ANY);
    }

    // Drop the registration packet (or pass it if you want the app to see it)
    return XDP_DROP;
}

// --- Path Management Program (for userspace to add paths) ---

SEC("xdp")
int specular_add_path(struct xdp_md *ctx) {
    // This program can be triggered via a special control packet
    // or paths can be added via userspace map manipulation.
    // For now, this is a placeholder - paths are added via the
    // main ingress path when packets arrive from new source IPs.
    return XDP_PASS;
}

char _license[] SEC("license") = "GPL";
