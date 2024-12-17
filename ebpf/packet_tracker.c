#include <linux/bpf.h>
#include <bpf/bpf_helpers.h>
#include <linux/if_ether.h>
#include <bpf/bpf_helpers.h>
#include <linux/ip.h>
#include "bpf_endian.h"
#include <linux/tcp.h>
// #define bpf_htons(x) __builtin_bswap16(x)

struct packet_info
{
    __u32 src_ip;
    __u32 dst_ip;
    __u16 src_port;
    __u16 dst_port;
};

struct event
{
    int pid;
} __attribute__((packed));

#define MAX_CPUS 128

// struct
// {
//     __uint(type, BPF_MAP_TYPE_PERF_EVENT_ARRAY);
//     __type(key, int);
//     __type(value, struct event);
//     __uint(max_entries, MAX_CPUS);
// } events SEC(".maps");

struct {
    __uint(type, BPF_MAP_TYPE_RINGBUF);
    __uint(max_entries, 512 * 1024 /* 256 KB */);
} events SEC(".maps");

SEC("xdp")
int hello_world(struct xdp_md *ctx)
{
    void *data = (void *)(long)ctx->data;
    void *data_end = (void *)(long)ctx->data_end;
    if (data < data_end)
    {
        // struct event e = {};
        // e.pid = 2;
        int e = 2;

        // __u64 flags = BPF_F_CURRENT_CPU;
        // __u16 sample_size = (__u16)(data_end - data);
        // flags |= (__u64)sample_size << 32;

        // bpf_printk("Packet info: src_ip=%u, dst_ip=%u\n", pkt_info.src_ip, pkt_info.dst_ip);
        // int ret = bpf_perf_event_output(ctx, &events, flags, &e, sizeof(e));
        // if (ret)
        //     bpf_printk("perf_event_output failed: %d\n", ret);

        int ret = bpf_ringbuf_output(&events, &e, sizeof(e),0);
        // if(ret != 0) {
            bpf_printk("bpf_ringbuf_output : %d\n", ret);
        // }
    }

    // bpf_ringbuf_output(&events, &e, sizeof(e),0);
    return XDP_PASS; // Allow packet to pass through
}

char LICENSE[] SEC("license") = "GPL";