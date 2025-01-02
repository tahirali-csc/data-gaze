#include "vmlinux.h"
// #include <linux/if_ether.h>
// #include <linux/ip.h>
// #include <linux/udp.h>
// #include <linux/tcp.h>
// #include <linux/bpf.h>
// #include <linux/if_packet.h>
// #include <linux/ptrace.h>
// #include <linux/types.h>
// #include <linux/if.h>
#include <bpf/bpf_helpers.h>
// #include <linux/in.h>


SEC("tracepoint/sock/inet_sock_set_state")
int inet_sock_set_state(struct trace_event_raw_inet_sock_set_state *args)
{
    return 0;
}