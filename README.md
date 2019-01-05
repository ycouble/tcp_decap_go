# S7 Variable Activity Tracker
Based on gopacket, this small program dissects a pcap and extracs the S7 payload, assuming a S7 stack based on TCP/IP.
The program only treats a few usecases, and makes the following assumptions regarding the S7 format:

1. Only Class 0 ISO-COTP Data TPDU are used (which is the scenario envisioned by RFC1005)
2. S7 Items Transport Size is alwyas 0x04, i.e. BYTE encoded
3. S7 syntax is always S7ANY
4. There are no errors in the variable reads/writes
5. S7 Variable specification format is always 0x12, with an adress format length of 10

## Usage
```(bash)
tcp_decap_go -r <filename.pcap> [-f] [-n N] [-d] [-v]
```
- -r is mandatory, followed by filename
- -f prints only the first packet found in the pcap
- -n N enables to only process the N-th packet of the pcap
- -d Displays the table obtained by the S7 processor (Variable Reads + Writes)
- -v Displays additional information obtained during the packet dissection
