#include "headers/nat_parse_helpers.h"
#include "headers/nat_maps.h"
#include "headers/lib_net_def.h"

char __license[] SEC("license") = "Dual MIT/GPL";


// Since the bpf program only track send packet, so this may not correct.
// However for now we just need to track connection changes to TIME_WAIT/CLOSE to gc conntrack map.
static __always_inline void update_conntrack_tcp_state(struct conntrack_value_t *conn_value, struct tcphdr *tcph) {
    // if (conn_value->tcp_state == 0)
    //     conn_value->tcp_state = TCP_CLOSE;

    // if (tcph->rst) {
    //     conn_value->tcp_state = TCP_CLOSE;
    //     return;
    // }

    // switch (conn_value->tcp_state) {
    //     case TCP_CLOSE:
    //         if (tcph->syn && tcph->ack)
    //             conn_value->tcp_state = TCP_SYN_RECV;
    //         else if (tcph->syn)
    //             conn_value->tcp_state = TCP_SYN_SENT;
    //         break;
    //     case TCP_SYN_SENT:
    //         if (tcph->ack)
    //             conn_value->tcp_state = TCP_ESTABLISHED;
    //         break;
    //     // not correct
    //     case TCP_SYN_RECV:
    //         if (tcph->ack)
    //             conn_value->tcp_state = TCP_ESTABLISHED;
    //         break;
    //     case TCP_ESTABLISHED:
    //         break;
        
    // }
}


// change conntrack tcp state. Delete entry if state is closed
static __always_inline void update_conntrack_state(bool is_lan, struct conntrack_key_t *conn_key, struct conntrack_value_t *conn_value, struct iphdr *iph, struct tcphdr *tcph) {
    // if in map, check tcp flag, update tcp status
    if (tcph) {
        update_conntrack_tcp_state(conn_value, tcph);
    }

    conn_value->timestamp = bpf_ktime_get_ns();

    // if (is_lan)
    //     if (bpf_map_update_elem(&ct_map_lan, conn_key, conn_value, BPF_ANY))
    //         bpf_printk("update internal conntrack map error\n");
    // else
    //     if (bpf_map_update_elem(&ct_map_wan, conn_key, conn_value, BPF_ANY))
    //         bpf_printk("update external conntrack map error\n");
}


// Check if conn is tracked (both ingress and egress map), and if tracked update conntrack map
static __always_inline bool check_conntrack_lan(struct conntrack_key_t *conn_key, struct conntrack_value_t *conn_value, struct iphdr *iph, struct tcphdr *tcph) {
    conn_value = bpf_map_lookup_elem(&ct_map_lan, conn_key);
    if (conn_value) {
        // TODO
        update_conntrack_state(true, conn_key, conn_value, iph, tcph);
        return true;
    }

    return false;
}


SEC("lan")
int nat_lan(struct __sk_buff *skb) {
    void *data_end = (void *)(long)skb->data_end;
    void *data = (void *)(long)skb->data;
    struct iphdr *iph;
    struct tcphdr *tcph;
    struct conntrack_key_t conn_key = {0};
    struct conntrack_value_t conn_value = {0};

    struct ethhdr *eth = data;
    if ((void *)(eth + 1) > data_end)
        return TC_ACT_OK;

    if (eth->h_proto != bpf_htons(ETH_P_IP))
        return TC_ACT_OK;

    if (__revalidate_data_pull(skb, &data, &data_end, (void *)&iph, sizeof(struct iphdr), sizeof(struct tcphdr), true))
        return TC_ACT_OK;

    if ((void *)(iph + 1) > data_end)
        return TC_ACT_OK;
    
    // TODO support udp, icmp
    if (iph->protocol != IPPROTO_TCP)
        return TC_ACT_OK;

    tcph = data + sizeof(*eth) + sizeof(*iph);
    if ((void *)(tcph + 1) > data_end)
        return TC_ACT_OK;

    conn_key.proto = iph->protocol;
    conn_key.saddr = bpf_ntohl(iph->saddr);
    conn_key.sport = bpf_ntohs(tcph->source);

    bool is_tracked = check_conntrack(&conn_key, &conn_value, iph, tcph);

    // check if in conntrack
        // not in, and tcp bit is syn, create 2 map entries (lan, wan conntrack)

        // in, update timestamp and tcp flags
    
    // update tcp flags
        // initiator (suppose lan) send syn -> tx_syn bit, wan send syn & ack -> rx_syn bit, lan send ack -> estab
        // suppose lan side send syn -> tx_fin bit, rx_fin bit can only be updated on the other side fin (need to consider fin retransfer)
        // add fin_ack bit? rx_fin_ack or tx_fin_ack
        // any side send rst: closed. Remove connection
}