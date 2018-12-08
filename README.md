# tcp_decap_go
PCAP decapsulator, a tcpdump like tool to display basic information, using the gopacket library.
This is just a training project, to practice go and gopacket. It could serve as an example file to start with gopacket.

## Usage
```(bash)
tcp_decap_go -r <filename.pcap> [-f]
```
- -r is mandatory, followed by filename
- -f prints only the first packet found in the pcap
