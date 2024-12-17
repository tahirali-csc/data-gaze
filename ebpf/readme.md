**Install Kernel Headers**
```bash
sudo apt update
sudo apt install linux-headers-$(uname -r)
```

**bpf_helpers.h and other eBPF utility headers are part of the libbpf package.**

```bash
sudo apt install libbpf-dev
```

**Issues**

asm/types.h Error during compilation of ebpf code 

https://stackoverflow.com/questions/77454504/asm-types-h-error-during-compilation-of-ebpf-code


**bpftool**

https://thegraynode.io/posts/bpf_bpftool/

list bppf maps

```
sudo bpftool map show
sudo bpftool map dump id 158
```