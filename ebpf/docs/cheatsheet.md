## bpftool
Useful information about `bpftool`
https://thegraynode.io/posts/bpf_bpftool/

## Useful commands

list and show bppf maps

```bash
sudo bpftool map show
sudo bpftool map dump id <map_id>
```

list program on network interface
```bash
sudo bpftool net list dev <iface>
```

read trace logs
```bash
sudo cat /sys/kernel/debug/tracing/trace_pipe
```