//Kachan Rostyslav xkacha02
//ISA 2024

#ifndef ISA_SIGNALHANDLER_H
#define ISA_SIGNALHANDLER_H
#include "SaveFile.h"
#include <iostream>
#include <set>
#include <pcap.h>
#include <csignal>
using namespace std;
/// @brief Handles program termination signals
void signalHandler(int signum);
extern string domainsfile;
extern string translationsfile;
extern set<string> uniqueDomains;
extern set<string> DomainToIP;
extern pcap_t* handle;
extern struct bpf_program filter;
/// @brief Enumeration of DNS record types
enum DnsRecordType {

    A = 1,
    NS = 2,
    CNAME = 5,
    SOA = 6,
    MX = 15,
    AAAA = 28,
    SRV = 33
};
/// @brief Enumeration of DNS classes
enum DnsClass {
    IN = 1,
    CS = 2,
    CH = 3,
    HS = 4
};
/// @brief Help structure for DNS data processing
struct hlp{
    int size;
    unsigned char* ptr;
    string name;
};
#endif //ISA_SIGNALHANDLER_H
