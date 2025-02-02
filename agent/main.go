package main

import (
	"agent/pkg/packetsender"
	"agent/pkg/program"
	"agent/pkg/reader"
	"flag"
	"fmt"
	"log"
)

func main() {
	// Define a string flag for the file name
	file := flag.String("file", "packet_tracker.o", "ELF file")

	// Define a string flag for the file name
	iface := flag.String("iface", "enp0s3", "ELF file")

	coll, err := program.Load(*file)
	if err != nil {
		log.Fatalf("Failed to load eBPF program: %v", err)
	}
	defer coll.Close()

	prog := coll.Programs["capture_packet"]
	if prog == nil {
		log.Fatalf("Program 'capture_packet' not found")
	}

	link, err := program.Attach(prog, *iface)
	defer link.Close()

	reader, err := reader.NewPacketReader(coll.Maps["ringbuf"])
	defer reader.Close()

	client := packetsender.NewClient("http://localhost:8080/connections")

	for {
		data, err := reader.Read()
		if err != nil {
			fmt.Println("error reading packet::", err)
			continue
		}
		// fmt.Println(data)

		if err = client.Send(data); err != nil {
			log.Println(err)
		}

	}
}
