//Kachan Rostyslav xkacha02
//ISA 2024

#include "PacketHandler.h"
/// @brief Handles incoming packets, extracts IP and DNS headers, and displays packet information
/// @param userData Pointer to user-defined data (unused)
/// @param pkthdr Pointer to the packet header containing metadata
/// @param packet Pointer to the raw packet data
void packetHandler(u_char* userData, const struct pcap_pkthdr* pkthdr, const u_char* packet) {
    char timeString[64];
    std::time_t rawtime = pkthdr->ts.tv_sec;
    struct tm* timeinfo = localtime(&rawtime);
    strftime(timeString, sizeof(timeString), "%Y-%m-%d %H:%M:%S", timeinfo);
    const unsigned char* ipHeaderStart = packet + 14;

    int ipVersion = (*ipHeaderStart) >> 4;

    if (ipVersion == 4) {
        const struct ip* ipHeader = (struct ip*)(ipHeaderStart);
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
        uint16_t rcode = flags & 0xF;

        bool isResponse = (flags >> 15) & 0x1;
        char qrType = isResponse ? 'R' : 'Q';

        uint16_t qCount = ntohs(dnsHeader->q_count);
        uint16_t ansCount = ntohs(dnsHeader->ans_count);
        uint16_t authCount = ntohs(dnsHeader->auth_count);
        uint16_t addCount = ntohs(dnsHeader->add_count);

        unsigned char* ptr_end_hdr = (unsigned char*)dnsHeader + sizeof(dnshdr);
        unsigned char* ptr_Header = (unsigned char*)dnsHeader;
        unsigned char* ptr = ptr_end_hdr;



        if (full_mode) {
            cout << "Timestamp: " << timeString << endl;
            cout << "SrcIP: " << srcIP << endl;
            cout << "DstIP: " << destIP << endl;
            cout << "SrcPort: UDP/" << std::dec << srcPort << endl;
            cout << "DstPort: UDP/" << std::dec << dstPort << endl;
            cout << "Identifier: 0x" << std::hex << std::uppercase<< ID << endl;
            std::cout << "Flags: QR=" << int(isResponse)
                      << ", OPCODE=" << opcode
                      << ", AA=" << aa
                      << ", TC=" << tc
                      << ", RD=" << rd
                      << ", RA=" << ra
                      << ", AD=" << ad
                      << ", CD=" << cd
                      << ", RCODE=" << rcode
                      << std::endl;
            if (qCount != 0) {

                ptr = processDNSQuestions(qCount,ptr,ptr_Header);            }

            if (ansCount != 0) {
                ptr = processDNSSections(ansCount,ptr, ptr_Header, ANS);
            }
            if(authCount != 0){
                ptr = processDNSSections(authCount,ptr, ptr_Header, AUTH);
            }
            if(addCount != 0){
                ptr = processDNSSections(addCount,ptr, ptr_Header,ADD);
            }
            cout << "==================== " << endl;
        } else {
            std::cout << timeString << " " << srcIP << " -> " << destIP << " (" << qrType << " " << qCount << "/" << ansCount << "/" << authCount << "/" << addCount << ")" << std::endl;
            if(!domainsfile.empty() || !translationsfile.empty())
            {
                if (qCount != 0) {

                    ptr = processDNSQuestions(qCount,ptr,ptr_Header);            }

                if (ansCount != 0) {
                    ptr = processDNSSections(ansCount,ptr, ptr_Header, ANS);
                }
                if(authCount != 0){
                    ptr = processDNSSections(authCount,ptr, ptr_Header, AUTH);
                }
                if(addCount != 0){
                    ptr = processDNSSections(addCount,ptr, ptr_Header,ADD);
                }
        }   }
    }
    else if(ipVersion == 6) {

        const struct ip6_hdr* ip6Header = (struct ip6_hdr*)ipHeaderStart;
        char srcIP[INET6_ADDRSTRLEN];
        char destIP[INET6_ADDRSTRLEN];


        inet_ntop(AF_INET6, &(ip6Header->ip6_src), srcIP, INET6_ADDRSTRLEN);
        inet_ntop(AF_INET6, &(ip6Header->ip6_dst), destIP, INET6_ADDRSTRLEN);

        const struct udphdr *udpHeader = (struct udphdr *) (packet + 14 + sizeof(struct ip6_hdr));
        uint16_t srcPort = ntohs(udpHeader->uh_sport);
        uint16_t dstPort = ntohs(udpHeader->uh_dport);
        const struct dnshdr *dnsHeader = (struct dnshdr *) (packet + 14 + sizeof(struct ip6_hdr) + sizeof(struct udphdr));

        uint16_t ID = ntohs(dnsHeader->id);
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

        unsigned char *ptr_end_hdr = (unsigned char *) dnsHeader + sizeof(dnshdr);
        unsigned char *ptr_Header = (unsigned char *) dnsHeader;
        unsigned char *ptr = ptr_end_hdr;



        if (full_mode) {
            cout << "Timestamp: " << timeString << endl;
            cout << "SrcIP: " << srcIP << endl;
            cout << "DstIP: " << destIP << endl;
            cout << "SrcPort: UDP/"  << std::dec << srcPort << endl;
            cout << "DstPort: UDP/" << std::dec << dstPort << endl;
            cout << "Identifier: 0x" << std::hex << std::uppercase << ID << endl;
            std::cout << "Flags: QR=" << int(isResponse)
                      << ", OPCODE=" << opcode
                      << ", AA=" << aa
                      << ", TC=" << tc
                      << ", RD=" << rd
                      << ", RA=" << ra
                      << ", AD=" << ad
                      << ", CD=" << cd
                      << ", RCODE=" << rcode
                      << std::endl;
            if (qCount != 0) {

                ptr = processDNSQuestions(qCount,ptr,ptr_Header);
            }

            if (ansCount != 0) {
                ptr = processDNSSections(ansCount,ptr, ptr_Header, ANS);
            }
            if(authCount != 0){
                ptr = processDNSSections(authCount, ptr, ptr_Header, AUTH);
            }
            if(addCount != 0){
                ptr = processDNSSections(addCount, ptr, ptr_Header,ADD);
            }
            cout << "==================== " << endl;
        } else {
            std::cout << timeString << " " << srcIP << " -> " << destIP << " (" << qrType << " " << qCount << "/"
                      << ansCount << "/" << authCount << "/" << addCount << ")" << std::endl;

            if(!domainsfile.empty() || !translationsfile.empty())
            {
                if (qCount != 0) {

                    ptr = processDNSQuestions(qCount,ptr,ptr_Header);            }

                if (ansCount != 0) {
                    ptr = processDNSSections(ansCount,ptr, ptr_Header, ANS);
                }
                if(authCount != 0){
                    ptr = processDNSSections(authCount,ptr, ptr_Header, AUTH);
                }
                if(addCount != 0){
                    ptr = processDNSSections(addCount,ptr, ptr_Header,ADD);
                }
            }
        }
    }
}
