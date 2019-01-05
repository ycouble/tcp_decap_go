# S7 Variable Activity Tracker
Based on gopacket, this small program dissects a pcap and extracs the S7 payload, assuming a S7 stack based on TCP/IP (i.e. based RFC 1006 and 905 for adaptation layers TKTP and ISO-COTP).
The program only treats a few usecases, and makes the following assumptions regarding the S7 format:

1. Only Class 0 ISO-COTP Data TPDU are used (which is the scenario envisioned by RFC1006)
2. S7 Items Transport Size is alwyas 0x04, i.e. BYTE encoded
3. S7 syntax is always S7ANY
4. There are no errors in the variable reads/writes
5. S7 Variable specification format is always 0x12, with an adress format length of 10

Only 4 types of S7 PDUs formats are supported:
- Job PDUs carrying functions Read Var or Write Var
- Ack_Data PDUs corresponding to the same functions

## Usage
To build, use `go build`

### CLI Usage
```(bash)
tcp_decap_go -r <filename.pcap> [-f] [-n N] [-d] [-v]
```
- -r is mandatory, followed by filename
- -f prcesses only the first packet found in the pcap
- -n N enables to only process the N-th packet of the pcap
- -d Displays the table obtained by the S7 processor (Variable Reads + Writes)
- -v Displays additional information obtained during the packet dissection

### Inside another go package
**Not tested**

The S7 Processor can be used by calling the following function:
```(go)
tcp_decap_go.func ExtractS7VariableReadWrite (fname *string, first *bool, packet_id *int, verbose *bool)
```
which returns a slice of tcp_decap_go.S7Item 

## Output format

```(go)
type S7Item struct {
    rname string    // ROSCTR name (e.g. Job or Ack_Data)
    fname string    // Function name (e.g. Read Var or Write Var)
    pduref int      // PDU identifier 
    itemid int      // Item identifier (item number in the PDU)
    status uint8    // Item Status 
    dbid int        // Database Identifier
    area uint8      // Area Identifier
    trsize int      // Transport size (e.g. 0x04 for BYTE)
    adress string   // Varaible Adress (Hexadecimal representation)
    objlen int      // Object length (Size in bytes)
    data string     // Data carried (Hexadecimal representation)
}
```

### Example Output
For the following packet:
![packet](http://couble.eu/assets/packet.png)

The programm outputs:
```
$ ./tcp_decap_go -r ../../data/s7comm_varservice_libnodavedemo_bench.pcap -d -n 4776
{fname:ReadVar rname:Job pduref:2350 itemid:0 status:0 dbid:0 area:129 trsize:2 adress:000000 objlen:0 data:}
{fname:ReadVar rname:Job pduref:2350 itemid:1 status:0 dbid:0 area:131 trsize:2 adress:000000 objlen:0 data:}
{fname:ReadVar rname:Job pduref:2350 itemid:2 status:0 dbid:0 area:131 trsize:2 adress:000030 objlen:0 data:}
{fname:ReadVar rname:Job pduref:2350 itemid:3 status:0 dbid:0 area:131 trsize:2 adress:000020 objlen:6 data:}
{fname:ReadVar rname:Job pduref:2350 itemid:4 status:0 dbid:0 area:131 trsize:2 adress:000020 objlen:0 data:}
```
Unused fields are left blank.
