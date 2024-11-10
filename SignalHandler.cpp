//Kachan Rostyslav xkacha02
//ISA 2024
#include "SignalHandler.h"
/// @brief Handles termination signals, saves data to files, and performs cleanup
/// @param signum Signal number received
void signalHandler(int signum) {
    if(!domainsfile.empty()){
        saveDomainsIPToFile(domainsfile,true);
    }
    if(!translationsfile.empty()){
        saveDomainsIPToFile(translationsfile,false);
    }
    uniqueDomains.clear();
    DomainToIP.clear();

    pcap_freecode(&filter);
    pcap_close(handle);


    cout << "Catch SIGINT, SIGTERM, SIGQUIT" << endl;
    exit(signum);
}