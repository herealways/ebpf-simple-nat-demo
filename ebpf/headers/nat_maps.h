#include "bpf_helpers.h"
#include "vmlinux.h"

// Everything is host order
// For now only support TCP

typedef struct iface_info {
    int ifindex;
    unsigned int ipv4;
} iface_info;

// The current ebpf program attached iface info
volatile const iface_info DYN_CFG_CURR_IFACE;

// all wan ifaces, when lan creating conntrack entry, will use weighted lb to choose an iface
struct bpf_map_def wan_ifaces SEC("maps") = {
    .type = BPF_MAP_TYPE_ARRAY,
    .key_size = sizeof(int),
    .value_size = sizeof(iface_info),
    .max_entries = 64
};

typedef struct conntrack_key_t
{
    unsigned int saddr;
    unsigned short sport;
    // TODO support tcp, udp, icmp
    unsigned char proto;
} conntrack_key_t;

// TODO possible use one map? maintain 2 maps' state is difficult
// Only use proto + dst ip/port as key

typedef struct conntrack_value_t
{
    unsigned int daddr;
    // For lan map, its SNAT updated saddr, for wan map, its DNAT updated daddr
    unsigned int nat_addr;
    unsigned short dport;
    unsigned short nat_port;
    // For lan map its SNAT redirected wan ifindex. For wan map, its DNAT redirected lan ifindex
    u32 nat_ifindex;
    u16 reserved;
    // conntrack flags
    // TODO
    u16 is_wan_initiated:1, // if it is wan side initiated the conntection, usually it is lan
        rx_closing:1,
        tx_closing:1,
        // TODO how to know if ack is ack to fin? need to save fin's sequence num?
        // or study how cilium conntrack handle connection close?
        rx_fin_ack:1,
        tx_fin_ack:1,
        reserved:13;
    // Get by bpf_ktime_get_ns(), used for gc
    // TODO gc half open connections faster? any possible syn flood from wan?
    u64 timestamp;
} conntrack_value_t;

// e.g. 192.168.31.6:60000 -> SNAT 192.168.31.10:60000 -> 192.168.31.11:8080
struct bpf_map_def ct_map_lan SEC("maps") = {
    .type = BPF_MAP_TYPE_HASH,
    .key_size = sizeof(conntrack_key_t),
    .value_size = sizeof(conntrack_value_t),
    // TODO support config
    .max_entries = 1024,
};

// e.g. 192.168.31.11:8080 -> 192.168.31.10:60000 -> DNAT 192.168.31.6.60000
struct bpf_map_def ct_map_wan SEC("maps") = {
    .type = BPF_MAP_TYPE_HASH,
    .key_size = sizeof(conntrack_key_t),
    .value_size = sizeof(conntrack_value_t),
    .max_entries = 1024,
};