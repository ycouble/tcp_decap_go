package main

import (
    "flag"
    "fmt"
    "log"
    "io"
//    "github.com/google/gopacket"
//    "github.com/google/gopacket/layers"
    "github.com/google/gopacket/pcap"
//    "github.com/google/gopacket/tcpassembly"
)

var fname   = flag.String("r", "", "Filename to read from")
var first   = flag.Bool("f", false, "Decap only first packet")
var verbose = flag.Bool("v", false, "Display intermediate layers informations")

func main() {
    flag.Parse()
    if *fname == "" {
	fmt.Printf("Need an input file name: Format : tcp_decap -r <filename.pcap>\n")
	return
    }

    handleRead, err := pcap.OpenOffline(*fname)
    if err != nil {
	log.Fatal("PCAP OpenOffline error:", err)
	return
    }
    defer handleRead.Close()

    pkt := 0

    for {
	data, ci, err := handleRead.ReadPacketData()
	fmt.Println(data)
	switch {
	    case err == io.EOF:
		fmt.Printf("\nFinished the PCAP\n")
		return
	    case err != nil:
		log.Printf("Failed to read packet %d: %s", pkt, err)
		return
	    default:
		fmt.Println(data, ci)
		pkt++

	}
    }
}


