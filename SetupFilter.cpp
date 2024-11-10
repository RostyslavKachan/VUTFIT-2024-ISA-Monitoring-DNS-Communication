//Kachan Rostyslav xkacha02
//ISA 2024

#include "SetupFilter.h"
/// @brief Captures DNS packets from a specified network interface
/// @param interface Name of the network interface to capture packets from
void captureFromInterface(const std::string& interface) {
    char errbuf[PCAP_ERRBUF_SIZE];
    handle = pcap_open_live(interface.c_str(), BUFSIZ, 1, 1000, errbuf);
    if (handle == nullptr) {
        std::cerr << "ERR: Could not open device " << interface << ": " << errbuf << std::endl;
        return;
    }


    if (pcap_compile(handle, &filter, "udp port 53", 0, PCAP_NETMASK_UNKNOWN) == -1) {
        std::cerr << "ERR: Could not parse filter: " << pcap_geterr(handle) << std::endl;
        pcap_close(handle);
        return;
    }
    if (pcap_setfilter(handle, &filter) == -1) {
        std::cerr << "ERR: Could not install filter: " << pcap_geterr(handle) << std::endl;
        pcap_close(handle);
        return;
    }

    pcap_loop(handle, 0, packetHandler, nullptr);

    pcap_freecode(&filter);
    pcap_close(handle);
}
/// @brief Captures DNS packets from a specified pcap file
/// @param pcapfile Name of the pcap file to capture packets from
void captureFromFile(const std::string& pcapfile) {
    char errbuf[PCAP_ERRBUF_SIZE];
    handle = pcap_open_offline(pcapfile.c_str(), errbuf);
    if (handle == nullptr) {
        std::cerr << "ERR: Could not open file " << pcapfile << ": " << errbuf << std::endl;
        return;
    }


    if (pcap_compile(handle, &filter, "udp port 53", 0, PCAP_NETMASK_UNKNOWN) == -1) {
        std::cerr << "ERR: Could not parse filter: " << pcap_geterr(handle) << std::endl;
        pcap_close(handle);
        return;
    }
    if (pcap_setfilter(handle, &filter) == -1) {
        std::cerr << "ERR: Could not install filter: " << pcap_geterr(handle) << std::endl;
        pcap_close(handle);
        return;
    }

    pcap_loop(handle, 0, packetHandler, nullptr);

    pcap_freecode(&filter);
    pcap_close(handle);
}