//Kachan Rostyslav xkacha02
//ISA 2024

#include "SaveFile.h"
/// @brief Saves either unique domains or domain-to-IP mappings to a specified file
/// @param filename Name of the file to save the data
/// @param flag Determines what to save: true for unique domains, false for domain-to-IP mappings
void saveDomainsIPToFile(const std::string& filename, bool flag) {
    std::ofstream outFile(filename);
    if (!outFile) {
        std::cerr << "ERR: Couldnt open file " << filename << std::endl;
        return;
    }
    if(flag) {
        for (const auto &domain: uniqueDomains) {
            outFile << domain << std::endl;
        }
    }
    else{
        for (const auto &domainToIP: DomainToIP) {
            outFile << domainToIP << std::endl;
        }
    }
    outFile.close();

}
/// @brief Adds a domain-to-IP mapping to the set
/// @param domainName Domain name
/// @param ip IP address associated with the domain
void addDomainToIP(string domainName, string ip){
    domainName.pop_back();
    domainName = domainName + " " + ip;
    DomainToIP.insert(domainName);
}
/// @brief Adds a domain to the set of unique domains
/// @param domain Domain name to add
void addDomain(std::string domain) {
    domain.pop_back();
    uniqueDomains.insert(domain);
}