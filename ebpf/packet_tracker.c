#include <linux/if_ether.h>
#include <linux/ip.h>
#include <linux/udp.h>
#include <linux/tcp.h>
#include <linux/bpf.h>
#include <linux/if_packet.h>
#include <linux/ptrace.h>
#include <linux/types.h>
#include <linux/if.h>
#include <bpf/bpf_helpers.h>
#include <linux/in.h>


struct packet_t {
    __be32 src_ip;   // Source IP
    __be32 dst_ip;   // Destination IP
    __u16 src_port;  // Source Port (for TCP/UDP)
    __u16 dst_port;  // Destination Port (for TCP/UDP)
    __u32 pkt_size;  // Packet size
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

     // Check if the packet is TCP or UDP to extract ports
    if (ip->protocol == IPPROTO_TCP) {
        struct tcphdr *tcp = (struct tcphdr *)(ip + 1);
        
        // Ensure we have enough data for the TCP header
        if ((void *)(tcp + 1) > data_end) {
            return XDP_PASS;
        }

        // Extract source and destination ports for TCP
        pkt.src_port = tcp->source;
        pkt.dst_port = tcp->dest;
    } else if (ip->protocol == IPPROTO_UDP) {
        struct udphdr *udp = (struct udphdr *)(ip + 1);
        
        // Ensure we have enough data for the UDP header
        if ((void *)(udp + 1) > data_end) {
            return XDP_PASS;
        }

        // Extract source and destination ports for UDP
        pkt.src_port = udp->source;
        pkt.dst_port = udp->dest;
    } else {
        // Drop non-TCP/UDP packets if you're not interested in other protocols
        return XDP_PASS;
    }

    // Send packet data to ring buffer
    int ret = bpf_ringbuf_output(&ringbuf, &pkt, sizeof(pkt), 0);
    if (ret != 0) {
        return XDP_DROP;
    }

    return XDP_PASS;
}

char _license[] SEC("license") = "GPL";
