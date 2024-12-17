package main

import (
	"fmt"
	"log"
	"net"

	"github.com/cilium/ebpf"
	"github.com/cilium/ebpf/link"
	"github.com/cilium/ebpf/ringbuf"
)

// Define the Go representation of the packet_info struct
type PacketInfo struct {
	SrcIP   uint32
	DstIP   uint32
	SrcPort uint16
	DstPort uint16
}

func main() {
	// Load the eBPF object
	spec, err := ebpf.LoadCollectionSpec("packet_tracker.o")
	if err != nil {
		log.Fatalf("Failed to load eBPF object: %v", err)
	}
	// defer obj.Close()

	coll, err := ebpf.NewCollection(spec)
	if err != nil {
		log.Fatalf("Failed to load eBPF program: %v", err)
	}
	defer coll.Close()

	// Get a handle to the PERF_EVENT_ARRAY map
	// eventsMap, ok := coll.Maps["events"]
	// if !ok {
	// 	log.Fatalf("PERF_EVENT_ARRAY map not found in the eBPF program")
	// }

	// Set up a perf reader for the map
	// rd, err := perf.NewReader(eventsMap, os.Getpagesize())
	// if err != nil {
	// 	log.Fatalf("Failed to create perf reader: %v", err)
	// }
	// defer rd.Close()

	// // Set up signal handling to gracefully shut down
	// // sigCh := make(chan os.Signal, 1)
	// // signal.Notify(sigCh, os.Interrupt, syscall.SIGTERM)

	fmt.Println("Listening for events...")

	// // go func() {
	// for {
	// 	// Read from the perf buffer
	// 	record, err := rd.Read()
	// 	if err != nil {
	// 		// if perf.IsClosed(err) {
	// 		// 	break
	// 		// }
	// 		// if errors.Is(err, os.ErrClosed) {
	// 		// 	break
	// 		// }
	// 		// log.Printf("Failed to read from perf buffer: %v", err)
	// 		// continue
	// 	}

	// 	log.Printf("Raw data: %x", record.RawSample)

	// 	// Parse the raw data into the PacketInfo struct
	// 	// var pkt PacketInfo
	// 	// if err := binary.Read(bytes.NewReader(record.RawSample), binary.LittleEndian, &pkt); err != nil {
	// 	// 	log.Printf("Failed to decode packet info: %v", err)
	// 	// 	continue
	// 	// }

	// 	// // Print the packet information
	// 	// fmt.Printf("Packet Info:\n")
	// 	// fmt.Printf("  SrcIP: %d.%d.%d.%d\n", pkt.SrcIP>>24, (pkt.SrcIP>>16)&0xFF, (pkt.SrcIP>>8)&0xFF, pkt.SrcIP&0xFF)
	// 	// fmt.Printf("  DstIP: %d.%d.%d.%d\n", pkt.DstIP>>24, (pkt.DstIP>>16)&0xFF, (pkt.DstIP>>8)&0xFF, pkt.DstIP&0xFF)
	// 	// fmt.Printf("  SrcPort: %d\n", pkt.SrcPort)
	// 	// fmt.Printf("  DstPort: %d\n", pkt.DstPort)
	// }
	// // }()

	// Open ring buffer
	events, err := ringbuf.NewReader(coll.Maps["events"])
	if err != nil {
		log.Fatalf("failed to open ring buffer: %v", err)
	}
	defer events.Close()

	// Read from the ring buffer
	log.Println("Waiting for events...")
	for {
		record, err := events.Read()
		if err != nil {
			log.Fatalf("failed to read from ring buffer: %v", err)
		}
		log.Printf("Event: %s", record.RawSample)
	}

	// <-sigCh
	fmt.Println("Shutting down...")

}

func _main() {
	// Load the eBPF object
	spec, err := ebpf.LoadCollectionSpec("packet_tracker.o")
	if err != nil {
		log.Fatalf("Failed to load eBPF object: %v", err)
	}
	// defer obj.Close()

	coll, err := ebpf.NewCollection(spec)
	if err != nil {
		log.Fatalf("Failed to load eBPF program: %v", err)
	}
	defer coll.Close()

	// Get the XDP program
	prog := coll.Programs["hello_world"]
	if prog == nil {
		log.Fatalf("Program 'hello' not found")
	}

	// iface := "eth0"
	iface, err := net.InterfaceByName("enp0s3")
	if err != nil {
		log.Fatal(err)
	}

	// Attach the eBPF program to the network interface (e.g., "eth0")
	// iface := "eth0"
	link, err := link.AttachXDP(link.XDPOptions{
		Program:   prog,
		Interface: iface.Index,
		Flags:     link.XDPGenericMode,
	})
	if err != nil {
		log.Fatalf("Failed to attach XDP program: %v", err)
	}
	defer link.Close()

	log.Printf("eBPF program loaded and attached to %s", iface.Name)

	log.Println("Press Ctrl+C to exit")
	select {}

	// Print BPF debug messages
	// events := make(chan []byte)
	// rd, err := perf.NewReader(coll.Maps["events"], 4096)
	// if err != nil {
	// 	log.Fatalf("Failed to create perf event reader: %v", err)
	// }
	// defer rd.Close()

	// go func() {
	// 	for {
	// 		record, err := rd.Read()
	// 		if err != nil {
	// 			log.Fatalf("Failed to read from perf event reader: %v", err)
	// 		}
	// 		events <- record.RawSample
	// 	}
	// }()

	// for event := range events {
	// 	log.Printf("Event: %s", string(event))
	// }
}
