//Kachan Rostyslav xkacha02
//ISA 2024

#ifndef ISA_PROCESSDNSSECTIONS_H
#define ISA_PROCESSDNSSECTIONS_H
#include "SignalHandler.h"
#include "getDomain.h"
void selectRecordType(uint16_t type);
void selectClass(uint16_t Class);
unsigned char* processDNSSections(int Count, unsigned char* Ptr, unsigned char* end_hdr, int section);
unsigned char* processDNSQuestions(int questionCount, unsigned char* lastPtr, unsigned char* end_hdr);
#endif //ISA_PROCESSDNSSECTIONS_H
