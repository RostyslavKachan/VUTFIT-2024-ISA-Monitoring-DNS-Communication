//Kachan Rostyslav xkacha02
//ISA 2024
#ifndef ISA_SETUPFILTER_H
#define ISA_SETUPFILTER_H
#include "SignalHandler.h"
#include "PacketHandler.h"
void captureFromInterface(const std::string& interface);
void captureFromFile(const std::string& pcapfile);
#endif //ISA_SETUPFILTER_H
