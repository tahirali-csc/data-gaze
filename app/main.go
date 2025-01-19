package main

import (
	"app/pkg/program"
	"app/pkg/reader"
	"flag"
	"fmt"
	"log"

	"github.com/cilium/ebpf"
	"github.com/cilium/ebpf/link"
)

const programCapturePack = "capture_packet"

func main() {
	// Define a string flag for the file name
	file := flag.String("file", "data_gaze.o", "ELF file")

	// Define a string flag for the file name
	iface := flag.String("iface", "enp0s3", "ELF file")

	// Define a string flag for the file name
	progToLoad := flag.String("program", "handle_set_state", "eBPF program to load")

	coll, err := program.Load(*file)
	if err != nil {
		log.Fatalf("Failed to load eBPF program: %v", err)
	}
	defer coll.Close()

	if *progToLoad == programCapturePack {
		handleCapturePacket(coll, iface)
	} else {
		prog := coll.Programs["handle_set_state"]
		if prog == nil {
			log.Fatalf("Program 'handle_set_state' not found")
		}

		tp, err := link.Tracepoint("sock", "inet_sock_set_state", prog, nil)
		if err != nil {
			log.Fatalf("Failed to attach eBPF program to tracepoint: %v", err)
		}
		defer tp.Close()

		rdr := reader.NewNetSocketReader(coll.Maps["events"])
		rdr.Read()
	}
}

func handleCapturePacket(coll *ebpf.Collection, iface *string) {
	prog := coll.Programs[programCapturePack]
	if prog == nil {
		log.Fatalf("Program 'capture_packet' not found")
	}

	link, err := program.Attach(prog, *iface)
	if err != nil {
		log.Fatalf("Failed to attach prorgram: %v", err)
	}
	defer func() {
		if link != nil {
			link.Close()
		}
	}()

	reader, err := reader.NewPacketReader(coll.Maps["ringbuf"])
	defer reader.Close()

	for {
		data, err := reader.Read()
		if err != nil {
			fmt.Println("error reading packet::", err)
			continue
		}
		fmt.Println(data)
	}
}
