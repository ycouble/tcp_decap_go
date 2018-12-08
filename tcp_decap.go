package main

import (
    "flag"
    "fmt"
    "log"
    "strings"
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
	for _, layer := range packet.Layers(){
	    fmt.Printf("%s -- ", layer.LayerType())
	    // Display layer information, for the main layer types
	    switch layer.LayerType() {
		case layers.LayerTypeEthernet:
		    PrintEthInfo(layer.(*layers.Ethernet))
		case layers.LayerTypeIPv4:
		    PrintIPv4Info(layer.(*layers.IPv4))
		case layers.LayerTypeTCP:
		    PrintTCPInfo(layer.(*layers.TCP))
		case layers.LayerTypeUDP:
		    PrintUDPInfo(layer.(*layers.UDP))
		default:
		    fmt.Printf("Layer '%s' not implemented yet\n",
				layer.LayerType())
	    }
	}

	fmt.Printf("\n")
	// Packet present in data
	pkt++
	// Test for -f option
	if *first { return }
    }
}

func PrintEthInfo(layer *layers.Ethernet) {
    fmt.Printf("MAC SRC: %s\tMAC DST: %s\t", layer.SrcMAC, layer.DstMAC)
    fmt.Printf("EtherType: %s\n", layer.EthernetType)
}

func PrintIPv4Info(layer *layers.IPv4) {
    fmt.Printf("@IP SRC: %s\t@IP DST: %s\t", layer.SrcIP, layer.DstIP)
    fmt.Printf("Protocol: %s\n", layer.Protocol)
}

func PrintTCPInfo(layer *layers.TCP) {
    fmt.Printf("Port SRC: %s\tPort DST: %s\t", layer.SrcPort, layer.DstPort)
    flags := make([]string, 0, 8)
    switch {
	case layer.SYN:
	    flags = append(flags,"SYN")
	case layer.ACK:
	    flags = append(flags,"ACK")
	case layer.RST:
	    flags = append(flags,"RST")
	case layer.PSH:
	    flags = append(flags,"PSH")
	case layer.FIN:
	    flags = append(flags,"FIN")
	case layer.ECE:
	    flags = append(flags,"ECE")
	case layer.URG:
	    flags = append(flags,"URG")
	case layer.CWR:
	    flags = append(flags,"CWR")
	case layer.NS:
	    flags = append(flags,"NS")
    }
    fmt.Printf("Flags: %s\t", strings.Join(flags, ", "))
    fmt.Printf("Payload size: %d\n", len(layer.BaseLayer.Payload))

}

func PrintUDPInfo(layer *layers.UDP) {
    fmt.Println("Not Implemented Yet")
}

