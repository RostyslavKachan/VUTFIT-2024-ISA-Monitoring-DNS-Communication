//Kachan Rostyslav xkacha02
//ISA 2024

#ifndef ISA_PACKETHANDLER_H
#define ISA_PACKETHANDLER_H
#include "SignalHandler.h"
#include "ProcessDNSSections.h"
#include <iostream>
#include <netinet/ip.h>
#include <netinet/ip6.h>
#include <netinet/udp.h>
#include <arpa/inet.h>
#include <ctime>

using namespace std;
extern bool full_mode;
/// @brief Enumeration representing different DNS sections
enum DNSSections{
    ANS = 1,
    AUTH = 2,
    ADD = 3
};
/// @brief Structure representing a DNS header
struct dnshdr {
    uint16_t id;
    uint16_t flags;
    uint16_t q_count;
    uint16_t ans_count;
    uint16_t auth_count;
    uint16_t add_count;
};
void packetHandler(u_char* userData, const struct pcap_pkthdr* pkthdr, const u_char* packet);
#endif //ISA_PACKETHANDLER_H
