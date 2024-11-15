# ISA 2024 Monitoring DNS communication
### Author: Rostyslav Kachan xkacha02
### Date: 15.11.2024
## Short description
Program `dns-monitor` monitors DNS communication on the selected interface or process DNS messages from an existing communication record in the PCAP format.
The tool  processes DNS messages and extract the information obtained from them. In addition, the tool determinates what domain names appeared in DNS messages. The third functionality is  searching  translations of domain names to IPv4/6 addresses.
The program has three possible outputs:
- standard output with information about DNS messages,
- (optionally) a file with spotted domain names and
- (optionally) a file with domain name to IP address translations.

## Usage examples
The following examples show how the `dns-monitor` program can be run with different parameters.
### Example 1 : Monitoring DNS queries on the interface  
Monitoring DNS queries on interface (example `enp0s3`), not verbose mode:
```bash
./dns-monitor -i enp0s3
```
### Example 2 : Process DNS messages from existing PCAP file
Process DNS messages from existing communication record in the PCAP format(example `A_test.pcap`), not verbose mode:
```bash
./dns-monitor -p A_test.pcap
```
### Example 3 : Process DNS messages from existing PCAP file (verbose mode)
Write  complete listing of DNS message details, such as: identifier, flags, information about sections:
```bash
./dns-monitor -p A_test.pcap -v
```
### Example 4 : Process DNS messages from existing PCAP file and save domains to file 
Process DNS messages from PCAP file and save  domains to file(example `domains.txt`), not verbose mode:
```bash
./dns-monitor -p A_test.pcap -d domains.txt
```
### Example 5 : Process DNS messages from existing PCAP file (verbose mode)
Process DNS messages from PCAP file and save  translations of domains to IP addresses to file(example `translationsfile.txt`), not verbose mode
```bash
./dns-monitor -p A_test.pcap -t translationsfile.txt
```
## Description of the most interesting parts of the implementation
- The program terminates its execution (`-i` flag -> capturing from interface) when it receives the signals `SIGINT`, `SIGTERM`, a `SIGQUIT`.
- Writing to files (when running with the -i parameter) occurs at the end, in the function `signalHandler`   function, which catches the above signals.
- The program supports parsing of DNS records of type `A`, `AAAA`, `NS`, `MX`, `SOA`, `CNAME`, and `SRV`. Unsupported records are marked as `UNKNOWN type of record`.
## Restrictions
The program does not contain any restrictions.
## List of files
```
Makefile
main.cpp
PacketHandler.cpp
PacketHandler.h
ProcessDNSSections.cpp
ProcessDNSSections.h
SaveFile.cpp
SaveFile.h
SetupFilter.cpp
SetupFilter.h
SignalHandler.cpp
SignalHandler.h
getDomain.cpp
getDomain.h
```