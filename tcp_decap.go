package main

import (
    "flag"
    "fmt"
    "log"
//    "io"
    "github.com/google/gopacket"
    "github.com/google/gopacket/layers"
    "github.com/google/gopacket/pcap"
//    "github.com/google/gopacket/tcpassembly"
)

var fname   = flag.String("r", "", "Filename to read from")
var first   = flag.Bool("f", false, "Decap only first packet")
var verbose = flag.Bool("v", false, "Display intermediate layers informations")

func main() {
    flag.Parse()
    if *fname == "" {
	fmt.Printf("Need an input file name: Format : ",
		    "tcp_decap -r <filename.pcap>\n")
	return
    }

    handleRead, err := pcap.OpenOffline(*fname)
    if err != nil {
	log.Fatal("PCAP OpenOffline error:", err)
	return
    }
    defer handleRead.Close()

    pkt := 0

    // First, we need to create the packet decoder for Ethernet
    // What if not Ethernet ???
    var decoder gopacket.Decoder
    decoder, ok := gopacket.DecodersByLayerName["Ethernet"]
    if !ok {
	log.Fatalln("Bad decoder name ??!!")
    }
    // Generate the source from the pcap handle and the decoder
    // Reminder: a source is a struct composed of a packet data source 
    // (coming from online/file) and a decoder (LayerDecoder). It also has
    // a chan c and DecodeOptions
    source	    := gopacket.NewPacketSource(handleRead, decoder)
    source.Lazy	    = false
    source.NoCopy   = true
    source.DecodeStreamsAsDatagrams = true

    for packet := range source.Packets(){
	// PacketSource.Packets() returns a chan of max 1000 packets 
	fmt.Printf("Packet %d - %d Layers\n", pkt, len(packet.Layers()))
	for i, layer := range packet.Layers(){
	    fmt.Printf("-- Layer %d: %T\n", i, layer)
	    // Display layer information, for the main layer types
	    switch layer.LayerType() {
		case layers.LayerTypeEthernet:
		    PrintEthInfo(layer)
		case layers.LayerTypeIPv4:
		    PrintIPv4Info(layer)
		case layers.LayerTypeTCP:
		    PrintTCPInfo(layer)
		case layers.LayerTypeUDP:
		    PrintUDPInfo(layer)
		default:
		    fmt.Printf("Layer %s not implemented yet",
				layer.LayerType())
	    }
	}

	// Packet present in data
	pkt++
	// Test for -f option
	if *first { return }
    }
}

func PrintEthInfo(layer gopacket.Layer) {
    fmt.Printf("MAC SRC: %s\tMAC DST: %s", layer.SrcMAC, layer.DstMAC)
    fmt.Printf("EtherType: %s", layer.EthernetType)
}

func PrintIPv4Info(layer layers.LayerTypeIPv4) {
    fmt.Printf("@IP SRC: %s\t@IP DST: %s", layer.SrcIP, layer.DstIP)
    fmt.Printf("Protocol: %s", layer.Protocol)
}

func PrintTCPInfo(layer layers.LayerTypeTCP) {
    fmt.Println("Not Implemented Yet")
}

func PrintUDPInfo(layer layers.LayerTypeUDP) {
    fmt.Println("Not Implemented Yet")
}

