//Kachan Rostyslav xkacha02
//ISA 2024
#include <iostream>
#include <unistd.h>
#include <string>
#include <pcap.h>
#include <netinet/ip.h>   // For IP header
#include <netinet/udp.h>  // For UDP header
#include <arpa/inet.h>    // For inet_ntoa
#include <ctime>          // For time formatting
using namespace std;

bool full_mode = false;

struct dnshdr {
    uint16_t id;
    uint16_t flags;
    uint16_t q_count;
    uint16_t ans_count;
    uint16_t auth_count;
    uint16_t add_count;
};

enum DnsRecordType {
    A = 1,
    NS = 2,
    CNAME = 5,
    SOA = 6,
    MX = 15,
    AAAA = 28,
    SRV = 33
};

enum DnsClass {
    IN = 1,
    CS = 2,
    CH = 3,
    HS = 4
};

void selectRecordType(uint16_t qtype) {
    switch (qtype) {
        case A:
            cout << "A";
            break;
        case NS:
            cout << "NS";
            break;
        case CNAME:
            cout << "CNAME";
            break;
        case SOA:
            cout << "SOA";
            break;
        case MX:
            cout << "MX";
            break;
        case AAAA:
            cout << "AAAA";
            break;
        case SRV:
            cout << "SRV";
            break;
        default:
            return;
    }
}

void selectClass(uint16_t qclass) {
    switch(qclass) {
        case IN:
            cout << "IN";
            break;
        case CS:
            cout << "CS";
            break;
        case CH:
            cout << "CH";
            break;
        case HS:
            cout << "HS";
            break;
    }
}

void packetHandler(u_char* userData, const struct pcap_pkthdr* pkthdr, const u_char* packet) {
    char timeString[64];
    std::time_t rawtime = pkthdr->ts.tv_sec;
    struct tm* timeinfo = localtime(&rawtime);
    strftime(timeString, sizeof(timeString), "%Y-%m-%d %H:%M:%S", timeinfo);

    const struct ip* ipHeader = (struct ip*)(packet + 14);
    int ipHeaderLen = ipHeader->ip_hl * 4;

    std::string srcIP = inet_ntoa(ipHeader->ip_src);
    std::string destIP = inet_ntoa(ipHeader->ip_dst);

    const struct udphdr* udpHeader = (struct udphdr*)(packet + 14 + ipHeaderLen);

    uint16_t srcPort = ntohs(udpHeader->uh_sport);
    uint16_t dstPort = ntohs(udpHeader->uh_dport);

    const struct dnshdr* dnsHeader = (struct dnshdr*)(packet + 14 + ipHeaderLen + sizeof(struct udphdr));

    uint16_t ID= ntohs(dnsHeader->id);
    uint16_t flags = ntohs(dnsHeader->flags);
    uint16_t opcode = (flags >> 11) & 0xF;
    uint16_t aa = (flags >> 10) & 0x1;
    uint16_t tc = (flags >> 9) & 0x1;
    uint16_t rd = (flags >> 8) & 0x1;
    uint16_t ra = (flags >> 7) & 0x1;
    uint16_t ad = (flags >> 5) & 0x1;
    uint16_t cd = (flags >> 4) & 0x1;
    uint16_t rcode = (flags >> 3) & 0xF;
    bool isResponse = (flags >> 15) & 0x1;
    char qrType = isResponse ? 'R' : 'Q';

    uint16_t qCount = ntohs(dnsHeader->q_count);
    uint16_t ansCount = ntohs(dnsHeader->ans_count);
    uint16_t authCount = ntohs(dnsHeader->auth_count);
    uint16_t addCount = ntohs(dnsHeader->add_count);

    int qsize = 0;
    if (qCount != 0) {
        unsigned char* ptr = (unsigned char*)dnsHeader + sizeof(dnshdr);

        std::string qname = "";
        while (*ptr != 0) {
            qsize += *ptr + 1;
            int labelLength = *ptr;
            ptr++;
            for (int i = 0; i < labelLength; ++i) {
                qname += *ptr;
                ptr++;
            }
            qname += '.';
        }
        qsize += 5;
        ptr++;

        uint16_t qtype = ntohs(*(uint16_t*)ptr);
        ptr += 2;
        uint16_t qclass = ntohs(*(uint16_t*)ptr);
        ptr += 2;
    }

    if (ansCount != 0) {
        unsigned char* ptr = (unsigned char*)dnsHeader + sizeof(dnshdr) + qsize;
    }
    if (full_mode) {
        cout << "Timestamp: " << timeString << endl;
        cout << "SrcIP: " << srcIP << endl;
        cout << "DstIP: " << destIP << endl;
        cout << "SrcPort: UDP/" << std::dec << srcPort << endl;
        cout << "DstPort: UDP/" << std::dec << dstPort << endl;
        cout << "Identifier: 0x" << std::hex << ID << endl;
        cout << "Flags: QR=" << int(isResponse) << endl;
        cout << "Flags: OPCODE=" << opcode << endl;
        cout << "Flags: AA=" << aa << endl;
        cout << "Flags: TC=" << tc << endl;
        cout << "Flags: RD=" << rd << endl;
        cout << "Flags: RA=" << ra << endl;
        cout << "Flags: AD=" << ad << endl;
        cout << "Flags: CD=" << cd << endl;
        cout << "Flags: RCODE=" << rcode << endl;
        cout << "$$$$$$$$$$$$$$$$$$$$$$$$$$$$$$$$$$$$$$$$$$$$$$$$$$$$$$$44" << endl;
    } else {
        std::cout << timeString << " " << srcIP << " -> " << destIP << " (" << qrType << " " << qCount << "/" << ansCount << "/" << authCount << "/" << addCount << ")" << std::endl;
    }
}

void captureFromInterface(const std::string& interface) {
    char errbuf[PCAP_ERRBUF_SIZE];
    pcap_t* handle = pcap_open_live(interface.c_str(), BUFSIZ, 1, 1000, errbuf);
    if (handle == nullptr) {
        std::cerr << "Could not open device " << interface << ": " << errbuf << std::endl;
        return;
    }

    struct bpf_program filter;
    if (pcap_compile(handle, &filter, "udp port 53", 0, PCAP_NETMASK_UNKNOWN) == -1) {
        std::cerr << "Could not parse filter: " << pcap_geterr(handle) << std::endl;
        pcap_close(handle);
        return;
    }
    if (pcap_setfilter(handle, &filter) == -1) {
        std::cerr << "Could not install filter: " << pcap_geterr(handle) << std::endl;
        pcap_close(handle);
        return;
    }

    pcap_loop(handle, 0, packetHandler, nullptr);

    pcap_freecode(&filter);
    pcap_close(handle);
}

void captureFromFile(const std::string& pcapfile) {
    char errbuf[PCAP_ERRBUF_SIZE];
    pcap_t* handle = pcap_open_offline(pcapfile.c_str(), errbuf);
    if (handle == nullptr) {
        std::cerr << "Could not open file " << pcapfile << ": " << errbuf << std::endl;
        return;
    }

    struct bpf_program filter;
    if (pcap_compile(handle, &filter, "udp port 53", 0, PCAP_NETMASK_UNKNOWN) == -1) {
        std::cerr << "Could not parse filter: " << pcap_geterr(handle) << std::endl;
        pcap_close(handle);
        return;
    }
    if (pcap_setfilter(handle, &filter) == -1) {
        std::cerr << "Could not install filter: " << pcap_geterr(handle) << std::endl;
        pcap_close(handle);
        return;
    }

    pcap_loop(handle, 0, packetHandler, nullptr);

    pcap_freecode(&filter);
    pcap_close(handle);
}

int main(int argc, char* argv[]) {
    int opt;
    std::cout << "Hello, World!" << std::endl;
    bool interface_provided = false;
    bool pcapfile_provided = false;

    string interface;
    string pcapfile;
    string domainsfile;
    string translationsfile;

    while ((opt = getopt(argc, argv, "i:p:vd:t:")) != -1) {
        switch (opt) {
            case 'i':
                if (interface_provided) {
                    cerr << "ERR: Option -i specified more than once.\n";
                    return EXIT_FAILURE;
                }
                if (optarg[0] == '-') {
                    cerr << "ERR: Interface not specified after -i\n";
                    return EXIT_FAILURE;
                }
                interface = optarg;
                interface_provided = true;
                break;
            case 'p':
                if (pcapfile_provided) {
                    cerr << "ERR: Option -p specified more than once.\n";
                    return EXIT_FAILURE;
                }
                if (optarg[0] == '-') {
                    cerr << "ERR: Pcapfile not specified after -p\n";
                    return EXIT_FAILURE;
                }
                pcapfile = optarg;
                pcapfile_provided = true;
                break;
            case 'v':
                full_mode = true;
                break;
            case 'd':
                if (optarg[0] == '-') {
                    cerr << "ERR: Domainsfile not specified after -d\n";
                    return EXIT_FAILURE;
                }
                domainsfile = optarg;
                break;
            case 't':
                if (optarg[0] == '-') {
                    cerr << "ERR: Translationsfile not specified after -t\n";
                    return EXIT_FAILURE;
                }
                translationsfile = optarg;
                break;
            case 'h':
            default:
                cout << "Usage: ./dns-monitor (-i <interface> | -p <pcapfile>)\n";
                cout << "Optional:\n";
                cout << "-v Full information about dns packet\n";
                cout << "-v - verbose mode: complete listing of DNS message details;\n";
                cout << "-d <domainsfile> - the name of the domain name file\n";
                cout << "-t <translationsfile> - the name of the domain name to IP translation file\n";
                return EXIT_FAILURE;
        }
    }

    if (!interface_provided && !pcapfile_provided) {
        cerr << "ERR: Interface or pcapfile were not specified!\tUsage: ./dns-monitor (-i <interface> | -p <pcapfile>)\n";
        return EXIT_FAILURE;
    }
    if (interface_provided && pcapfile_provided) {
        cerr << "ERR: You cant use this 2 options! You have to choose only one)\tUsage: ./dns-monitor (-i <interface> | -p <pcapfile>)\n";
        return EXIT_FAILURE;
    }

    if (!interface.empty()) {
        captureFromInterface(interface);
    } else if (!pcapfile.empty()) {
        captureFromFile(pcapfile);
    }
    return 0;
}

