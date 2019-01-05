package main

import (
    "flag"
    "fmt"
    "log"
    "strings"
    "encoding/hex"
    "github.com/google/gopacket"
    "github.com/google/gopacket/layers"
    "github.com/google/gopacket/pcap"
)

var fname     = flag.String("r", "", "Filename to read from")
var first     = flag.Bool("f", false, "Decap only first packet")
var packet_id = flag.Int("n", -1, "Decap only packet N")
var verbose   = flag.Bool("v", false, "Display intermediate layers informations")
var disp_res  = flag.Bool("d", false, "Display results")

func main() {
    flag.Parse()
    if *fname == "" {
	fmt.Printf("Need an input file name: Format : ",
		    "tcp_decap -r <filename.pcap>\n")
	return
    }

    items := ExtractS7VariableReadWrite(fname, first, packet_id, verbose)

    if *disp_res {
	for _, item := range(items) {
	    fmt.Printf("%+v\n",item)
	}
    }

}

func ExtractS7VariableReadWrite (fname *string,
				 first *bool,
				 packet_id *int,
				 verbose *bool) []S7Item {

    // bool var to tell if we need to display only one packet
    var one_packet = *packet_id > 0

    handleRead, err := pcap.OpenOffline(*fname)
    if err != nil {
	log.Fatal("PCAP OpenOffline error:", err)
	return nil
    }
    defer handleRead.Close()

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

    // Iitialize output table, as a slice of S7 items
    output_S7items := make([]S7Item, 0, 1000)

    pkt := -1
    // Process packets one by one
    for packet := range(source.Packets()) {
	// PacketSource.Packets() returns a chan of max 1000 packets 

	pkt += 1
	// Check for option -n N to process only packet N
	if one_packet && pkt != *packet_id {
	    continue
	}

	// Check for option -v to, if true, display packet information of 
	// layers automatically decoded by gopacket (i.e. up to TCP)
	if *verbose {
	    PrintPacketInfo(packet, pkt)
	}

	// Additional processing goes HERE
	/*
	    S7 Protocol Recognition
	    (Assuming S7 stack == Eth<IP<TCP<TKTP<ISO-COTP(class0)<S7)
	    0) has this packet a TCP Payload ?
	    1) is this a TKTP Packet ? (tcp 102 as src or dst port)
	    2) is this a ISO-COTP Data TPDU ? (PDU Type = DT (i.e. =0x0f))
	    3) is this a S7 Telegram ? (First byte of TPDU User Data = 0x32)
	    
	*/
	has_tcp, tcp_pld := hasTCPPayload(packet)
	if !has_tcp {
	    continue
	}
	has_tktp, ver	 := hasTKTP(packet)
	if !has_tktp {
	    continue
	}
	has_dt, cotp_pld := hasDTPDU(tcp_pld)
	if !has_dt {
	    continue
	}
	has_s7, s7   := hasS7(cotp_pld)
	if !has_s7 {
	    continue
	}
	if *verbose || false {
	    fmt.Printf("Packet %d has TKTPv%d, ISO-COTP and S7 = %v\n", pkt, ver, s7)
	}

	/*
	    S7 Info Extraction
	    - is this a S7 Job or a S7 Ack ? (S7.ROSCTR = Job (1))
	    - Let's assume there are only 1 item per S7 PDU
	*/
	ok, S7items := processS7(s7)
	if ok {
	    output_S7items = append(output_S7items, S7items...)
	}

	// END additional processing
	// Check for -f option, and if true, stop processing packet
	if *first { break }
    }
    return output_S7items
}


/*
 **** Main Dissector: S7 processor
*/

type S7Item struct {
    fname string    // Function
    rname string    // ROSCTR name
    pduref int	    // PDU identifier
    itemid int	    // Item identifier
    status uint8    // Item Status
    dbid int	    // DB id
    area uint8	    // Area
    trsize int	    // Transport size
    adress string   // Varaible Adress
    objlen int	    // Object length
    data string     // Data carried
}

/*
S7 Format
Header (0-9 if ROSCTR=1(Job), 0-11 if ROSCTR=3(Ack_Data))
    0      1      2,3     4,5     6,7       8,9             10,11
+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-
| 0x32 | ROSCTR | Res | PDUref | ParLen | DataLen | Err (only if Ack_Data) |
+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-

Param (HDR_len - ParHdrFin = HDR_len+ParLen)
                 0                     2
+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-
| Function (ReadVar or WriteVar) | ItemCount | 
+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-

**Param items**
1) Job: ReadVar or WriteVar
     0         1              2        3     4,5   6,7    8     9,10,11
+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
| VarSpec | AddrLen(=10) | Syntax | TrSize | Len | DB# | Area | Address |
+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+

**Data items**
1) Job: WriteVar or Ack_Data: ReadVar
     0         1       2,3     4-4+(N-1)*TrSize (Assumed = 1 here)
+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-
| RetCode | TrSize | Len(=N) |                Data                 |
+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-
Note: RetCode = 0 for Job/WriteVar, doesn't need to be checked, but it
doesn't matter, so we might as well factor the code
2) Ack_Data: WriteVar
     0    
+-+-+-+-+-+
| RetCode |
+-+-+-+-+-+
*/
func processS7(data []uint8) (bool, []S7Item) {
    // Identify the type of S7 Telegram
    rosctr := data[1] // 0 is 0x32
    rname, hdr_len := getRosctrName(rosctr)
    if hdr_len == 0 {return false, nil}
    // Decode Hdr and Extract lengthes (header, param, data)
    pduref   := concat2(data[4], data[5])
    paramlen := concat2(data[6], data[7])
    //datalen  := concat2(data[8], data[9])
    param_start      := hdr_len
    param_item_start := param_start + 2 // 2 bytes for param headers
    data_start       := param_start + paramlen
    //end		     := data_start + datalen
    // DEBUG fmt.Printf("S7 telegram lengths : hdr=%d, param=%d, data=%d, tot=%d, real=%d\n",
    // DEBUG 	hdr_len, paramlen, datalen, end, len(data))
    // Read Param headers
    fname := getFunctionName(data[param_start])
    if fname == "" {return false, nil}
    item_count := data[param_start+1]
    S7items := make([]S7Item, item_count, 10)
    // Initialize common part
    for i,_ := range(S7items) {
        S7items[i].fname  = fname
        S7items[i].rname  = rname
        S7items[i].pduref = pduref
        S7items[i].itemid = i
    }
    // Decode Param Items, when applicable (otherwise it can be skipped, and we 
    // should have param_item_start == data_start
    if rname == "Job" {
	cur := param_item_start
	var addrlen int
	for i,_ := range(S7items) {
	    addrlen = int(data[cur+1])
	    // Since all Data items follow the same struncture when rname == Job
	    // We simply retrieve the information, regardless of several
	    // parameters contained in the S7 fields
	    S7items[i].trsize  = int(data[cur+3])
	    // data length is expressed in bits so we have to divide by 8 
	    // since TrSize is Byte
	    // XXX If Trsize not BYTE, then objlen should be adapted
	    S7items[i].objlen  = concat2(data[cur+4], data[cur+5])>>3
	    S7items[i].dbid    = concat2(data[cur+6], data[cur+7])
	    S7items[i].area    = data[cur+8]
	    S7items[i].adress  = hex.EncodeToString(data[cur+9:cur+12])
	    // Increment current position in cur
	    cur += 2 + addrlen
	    // DEBUG fmt.Printf("=== Item %d : %+v\n", i, S7items[i])
	}
    } else {
	// Nothing to do
    }
    // Decode Data Items, when applicable
    if rname == "Job" && fname == "WriteVar" ||
       rname == "Ack_Data" && fname == "ReadVar" {
	cur := data_start
	for i,_ := range(S7items) {
	    // /!\ S7 item may have been initialized already!
	    // However, the fields are distinct or identical, 
	    // so there shouldn't be any issue overwriting things
	    S7items[i].status = data[cur]
	    S7items[i].trsize = int(data[cur+1]) // overwrite
	    // XXX If Trsize not BYTE, then objlen should be adapted
	    S7items[i].objlen = concat2(data[cur+2],data[cur+3])>>3 // overwrite
	    S7items[i].data   = hex.EncodeToString(data[cur+4:cur+4+S7items[i].objlen])
	    // DEBUG fmt.Printf("=== Item %d : %+v\n", i, S7items[i])
	    // Increment current position in cur
	    cur += 4 + S7items[i].objlen
	   }
    } else if rname == "Ack_Data" && fname == "WriteVar" {
	cur := data_start
	for i,_ := range(S7items) {
	    S7items[i].status = data[cur]
	    cur += 1
	}
    } else {
	// Nothing to do
    }

    return true, S7items
}

/* Utility functions */
func concat2 (a uint8, b uint8) int {
    return int(a)<<8+int(b)
}
func concat3 (a uint8, b uint8, c uint8) int {
    return int(a)<<16+int(b)<<8+int(c)
}
func getRosctrName(rid uint8) (string, int) {
    switch rid {
	case 1: // Job
	    return "Job", 10
	case 3: // Ack_Data
	    return "Ack_Data", 12
	default:
	    fmt.Printf("Info: ROSCTR Unknown: %d\n", rid)
	    return "Unknown", 0
    }
}
func getFunctionName (fid uint8) string {
    switch fid {
	case 4:
	    return "ReadVar"
	case 5:
	    return "WriteVar"
	default:
	    fmt.Printf("Info: Function Name Unknown: %d\n", fid)
	    return ""
    }
}

/*
 **** Several Packet decoding and recognition functions
*/
/* Get TCP layer */
func getTCP (packet gopacket.Packet) *layers.TCP {
    return packet.TransportLayer().(*layers.TCP)
}

/* checks if the packet has a TCP Payload, and if it does, returns it */
func hasTCPPayload (packet gopacket.Packet) (bool, []uint8) {
    // Basic check
    if packet.NetworkLayer() == nil || packet.TransportLayer() == nil ||
	packet.TransportLayer().LayerType() != layers.LayerTypeTCP {
	    return false, nil
    }
    // Packet has TCP
    tcp := getTCP(packet)
    if len(tcp.BaseLayer.Payload) == 0 {
	return false, nil
    }
    // DEBUG fmt.Printf("%v\n", tcp.BaseLayer.Payload)
    // Packet has payload
    return true, tcp.BaseLayer.Payload

}

/* checks if the packet has a TKTP PDU in the TCP Payload (i.e. if port 102 is 
 used), and if it does, returns the TKTP version */
func hasTKTP (packet gopacket.Packet) (bool, uint8) {
    tcp := getTCP(packet)
    if tcp.SrcPort == 102 || tcp.DstPort == 102 {
	payload := tcp.BaseLayer.Payload
	return true, payload[0]
    } else {
	return false, 0
    }
}

/* checks if the payload contains ISO-COTP Data TPDU, and return it if 
 there is */
func hasDTPDU (payload []uint8) (bool, []uint8) {
    // TKTP
    //tktp    := payload[0:4] // First 4 bytes
    // ISO-COTP
    hdr_len := payload[4] // length N doesn't include COTP LI byte
    // Get COTP Headers
    cotp    := payload[4:5+hdr_len] // First N bytes are COTP headers
    // Extract TPDU identification code
    code    := cotp[1]>>4
    if code == 15 { // code == 15 <=> type == DT, see RFC 1006 and 905
	// retrieve COTP Payload, and return it
	return true, payload[5+hdr_len:]
    } else {
	return false, nil
    }
}

/* checks if the payload contains S7 data (first byte has to be
 0x32 (i.e. 50)) and returns the s7 payload if there is */
func hasS7 (cotp_payload []uint8) (bool, []uint8){
    if cotp_payload[0] == 50 {
	return true, cotp_payload
    } else {
	return false, nil
    }
}



/*
 **** Some simple display functions to debug ****
*/
func PrintPacketInfo (packet gopacket.Packet, pkt int) {
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
    if layer.SYN {
	flags = append(flags,"SYN")
    }
    if layer.ACK {
	    flags = append(flags,"ACK")
    }
    if layer.RST {
	    flags = append(flags,"RST")
    }
    if layer.PSH {
	    flags = append(flags,"PSH")
    }
    if layer.FIN {
	    flags = append(flags,"FIN")
    }
    if layer.ECE {
	    flags = append(flags,"ECE")
    }
    if layer.URG {
	    flags = append(flags,"URG")
    }
    if layer.CWR {
	    flags = append(flags,"CWR")
    }
    if layer.NS {
	    flags = append(flags,"NS")
    }
    fmt.Printf("Flags: [%s]\t", strings.Join(flags, ", "))
    fmt.Printf("Payload size: %d\n", len(layer.BaseLayer.Payload))

}

func PrintUDPInfo(layer *layers.UDP) {
    fmt.Println("Not Implemented Yet")
}

