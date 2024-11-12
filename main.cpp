// Kachan Rostyslav xkacha02
// ISA 2024

#include <iostream>
#include <unistd.h>
#include <string>
#include "SignalHandler.h"
#include "SetupFilter.h"
#include "SaveFile.h"
using namespace std;

/// @brief Enables verbose mode for detailed DNS packet output
bool full_mode = false;

/// @brief Set of unique domains captured from DNS packets
set<string> uniqueDomains;

/// @brief Set of domains mapped to IP addresses
set<string> DomainToIP;

/// @brief Pointer to pcap capture handle
pcap_t* handle;

/// @brief Packet filter program structure
struct bpf_program filter;

/// @brief Filename for saving domain names
string domainsfile;

/// @brief Filename for saving domain-to-IP translations
string translationsfile;

/// @brief Main function for DNS packet capture and processing
/// @param argc Number of command-line arguments
/// @param argv Array of command-line arguments
int main(int argc, char* argv[]) {

    int opt;

    /// @brief Sets up signal handlers
    std::signal(SIGTERM, signalHandler);
    std::signal(SIGINT, signalHandler);
    std::signal(SIGQUIT, signalHandler);

    bool interfaceProvided = false;   ///< @brief Indicates if a network interface was specified
    bool pcapfileProvided = false;    ///< @brief Indicates if a pcap file was specified

    string interface;                 ///< @brief Network interface name for capturing packets
    string pcapfile;                  ///< @brief Pcap file name for reading packets

    /// @brief Processes command-line options
    while ((opt = getopt(argc, argv, "i:p:vd:t:")) != -1) {
        switch (opt) {
            case 'i':
                if (interfaceProvided) {
                    cerr << "ERR: Option -i specified more than once.\n";
                    return EXIT_FAILURE;
                }
                if (optarg[0] == '-') {
                    cerr << "ERR: Interface not specified after -i\n";
                    return EXIT_FAILURE;
                }
                interface = optarg;
                interfaceProvided = true;
                break;
            case 'p':
                if (pcapfileProvided) {
                    cerr << "ERR: Option -p specified more than once.\n";
                    return EXIT_FAILURE;
                }
                if (optarg[0] == '-') {
                    cerr << "ERR: Pcapfile not specified after -p\n";
                    return EXIT_FAILURE;
                }
                pcapfile = optarg;
                pcapfileProvided = true;
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
                cout << "-v - verbose mode: complete listing of DNS message details;\n";
                cout << "-d <domainsfile> - the name of the domain name file\n";
                cout << "-t <translationsfile> - the name of the domain name to IP translation file\n";
                return EXIT_FAILURE;
        }
    }

    /// @brief Verifies that either an interface or pcap file was specified, not both
    if (!interfaceProvided && !pcapfileProvided) {
        cerr << "ERR: Interface or pcapfile were not specified!\tUsage: ./dns-monitor (-i <interface> | -p <pcapfile>)\n";
        return EXIT_FAILURE;
    }
    if (interfaceProvided && pcapfileProvided) {
        cerr << "ERR: You can't use both options! Choose one: interface or pcapfile.\n";
        return EXIT_FAILURE;
    }

    /// @brief Starts capturing based on the specified interface or pcap file
    if (!interface.empty()) {
        captureFromInterface(interface);
    } else if (!pcapfile.empty()) {
        captureFromFile(pcapfile);
    }

    /// @brief Saves captured domain or domain-to-IP data if filenames were provided
    if (!domainsfile.empty()) {
        saveDomainsIPToFile(domainsfile, true);
    }
    if (!translationsfile.empty()) {
        saveDomainsIPToFile(translationsfile, false);
    }

    return 0;
}
