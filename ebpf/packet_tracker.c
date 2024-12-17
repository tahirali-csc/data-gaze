#include <linux/bpf.h>
#include <bpf/bpf_helpers.h>
#include <linux/if_ether.h>
#include <linux/ip.h>

struct packet_t {
    __u32 src_ip;
    __u32 dst_ip;
    __u32 pkt_size;
};

struct {
    __uint(type, BPF_MAP_TYPE_RINGBUF);
    __uint(max_entries, 1 << 24);
} ringbuf SEC(".maps");

SEC("xdp")
int capture_packet(struct xdp_md *ctx) {
    void *data = (void *)(long)ctx->data;
    void *data_end = (void *)(long)ctx->data_end;
    struct ethhdr *eth = data;

    if ((void *)(eth + 1) > data_end) {
        return XDP_PASS;
    }

    if (eth->h_proto != __constant_htons(ETH_P_IP)) {
        return XDP_PASS;
    }

    struct iphdr *ip = (struct iphdr *)(eth + 1);
    if ((void *)(ip + 1) > data_end) {
        return XDP_PASS;
    }

    struct packet_t pkt = {};
    pkt.src_ip = ip->saddr;
    pkt.dst_ip = ip->daddr;
    pkt.pkt_size = (data_end - data);

    // Send packet data to ring buffer
    int ret = bpf_ringbuf_output(&ringbuf, &pkt, sizeof(pkt), 0);
    if (ret != 0) {
        return XDP_DROP;
    }

    return XDP_PASS;
}

char _license[] SEC("license") = "GPL";
