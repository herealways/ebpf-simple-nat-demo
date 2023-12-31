#include "bpf_helpers.h"
#include "if_ether.h"
#include "vmlinux.h"
#include "bpf_endian.h"

#define TCP_CSUM_OFF (ETH_HLEN + sizeof(struct iphdr) + offsetof(struct tcphdr, check))
#define IP_CSUM_OFF (ETH_HLEN + offsetof(struct iphdr, check))
#define IP_SRC_OFF (ETH_HLEN + offsetof(struct iphdr, saddr))
#define IP_DEST_OFF (ETH_HLEN + offsetof(struct iphdr, daddr))
#define TCP_DPORT_OFF (ETH_HLEN + sizeof(struct iphdr) + offsetof(struct tcphdr, dest))
#define IS_PSEUDO 0x10


static __always_inline int
__revalidate_data_pull(struct __sk_buff *skb, void **data_, void **data_end_,
                       void **l3, const __u32 l3_len, __u32 l4_len, const bool pull)
{
	const __u64 tot_len = ETH_HLEN + l3_len + l4_len;
	void *data_end;
	void *data;

	/* Verifier workaround, do this unconditionally: invalid size of register spill. */
	if (pull)
		bpf_skb_pull_data(skb, tot_len);
	data_end = (void*)((long)skb->data_end);
	data = (void*)((long)skb->data);
	if (data + tot_len > data_end)
		return -1;

	/* Verifier workaround: pointer arithmetic on pkt_end prohibited. */
	*data_ = data;
	*data_end_ = data_end;

	*l3 = data + ETH_HLEN;
	return 0;
}

static __always_inline int
__revalidate_data_l4(struct __sk_buff *skb, void **data_, void **data_end_,
					  void **l3, void **l4, const __u32 l3_len, __u32 l4_len, const bool pull)
{
	const __u64 tot_len = ETH_HLEN + l3_len + l4_len;
	void *data_end;
	void *data;

	if (pull)
		bpf_skb_pull_data(skb, tot_len);
	data_end = (void*)((long)skb->data_end);
	data = (void*)((long)skb->data);
	if (data + tot_len > data_end)
		return 1;
 
	/* Verifier workaround: pointer arithmetic on pkt_end prohibited. */
	*data_ = data;
	*data_end_ = data_end;

	*l3 = data + ETH_HLEN;
	*l4 = data + ETH_HLEN + l3_len;
	return 0;
}

// updated from https://elixir.bootlin.com/linux/latest/source/samples/bpf/xdp_fwd_kern.c#L40
/* from include/net/ip.h */
static __always_inline int ip_decrease_ttl(struct iphdr *iph)
{
	// TODO add back __force
	__u32 check = ( __u32)iph->check;
	// TODO add back __force
	check += ( __u32)bpf_htons(0x0100);
		// TODO add back __force
	iph->check = ( __sum16)(check + (check >= 0xFFFF));
	return --iph->ttl;
}