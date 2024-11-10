//Kachan Rostyslav xkacha02
//ISA 2024
#ifndef ISA_SAVEFILE_H
#define ISA_SAVEFILE_H
#include "SignalHandler.h"
#include <string>
#include <fstream>
using namespace std;
void saveDomainsIPToFile(const std::string& filename, bool flag);
void addDomainToIP(string domainName, string ip);
void addDomain(std::string domain);
#endif //ISA_SAVEFILE_H
