## Struct Padding
In eBPF (Extended Berkeley Packet Filter), a packed struct is a data structure where all of its fields are stored tightly together, without any extra spaces (padding) between them.

### Why Does Padding Happen in Normal Structs?
Normally, when you define a struct in programming languages like C, the compiler may add padding bytes between the fields to align them in memory for performance reasons. For example:

```c
struct example {
    char a;     // 1 byte
    int b;      // 4 bytes
};
```

Here, the compiler may add 3 padding bytes after a to align b to a 4-byte boundary. This is done to make memory access faster but increases the size of the struct.

Without padding: size = 5 bytes
With padding: size = 8 bytes

### What Is a Packed Struct?
A packed struct avoids this padding by forcing the compiler to store the fields back-to-back, without aligning them to specific memory boundaries. This means the struct uses only the memory required for its fields.

For example:

```c
struct __attribute__((packed)) example {
    char a;     // 1 byte
    int b;      // 4 bytes
};
```
Here, the `__attribute__((packed))` tells the compiler not to add padding. The size will now be 5 bytes, and the fields are stored exactly as defined.

### Why Use Packed Structs in eBPF?
eBPF programs often deal with data structures (like packet headers) that are tightly packed in memory. For example:

Network packet headers (e.g., Ethernet, IP, TCP) are laid out in a packed format according to protocol standards.
If an eBPF program accesses these headers using a normal struct (with padding), the field offsets will not match the actual packet layout, leading to incorrect data processing.
By defining structs as packed, eBPF programs can correctly map to these tightly packed network headers and access fields without any mismatch.