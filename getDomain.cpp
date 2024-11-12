//Kachan Rostyslav xkacha02
//ISA 2024

#include "getDomain.h"
/// @brief Extracts domain name information from a DNS packet, handling compression if present
/// @param startPtr Pointer to the start of the DNS packet
/// @param Ptr Pointer to the current position within the DNS packet
/// @return hlp structure containing domain name and pointer of dns packet
hlp getDomain(unsigned char* startPtr, unsigned char* Ptr) {
    hlp domain;
    domain.size = 0;
    domain.name = "";
    int checkNotEmpty = 0;
    hlp additional_struct_to_identif_comp;
    additional_struct_to_identif_comp.size = 0;
    additional_struct_to_identif_comp.name = "";

    unsigned char* originalPtr = Ptr;
    bool jumped = false;
    bool compression_on_start = false;


    while (*Ptr != 0) {
        if ((*Ptr & 0xC0) == 0xC0) {
            if (domain.size == 0) {

                compression_on_start = true;
            } else if (!jumped) {

                additional_struct_to_identif_comp.size = domain.size;
            }

            int offset = ((*Ptr & 0x3F) << 8) | *(Ptr + 1);
            Ptr = startPtr + offset;
            jumped = true;
        } else {
            int labelLength = *Ptr;
            if (labelLength > 63) {
                throw std::runtime_error("ERR: Invalid label length in NAME");
            }

            Ptr++;
            domain.size += labelLength + 1;

            for (int j = 0; j < labelLength; ++j) {
                domain.name += *Ptr;
                Ptr++;
            }
            domain.name += '.';
        }
        checkNotEmpty++;
    }
    if(checkNotEmpty == 0){
        Ptr++;
        domain.ptr = Ptr;
        domain.name+= '.';
    }
    else if (compression_on_start) {

        domain.ptr = originalPtr + 2;
    } else if (jumped) {

        domain.ptr = originalPtr + additional_struct_to_identif_comp.size + 2;
    } else {

        Ptr++;
        domain.size += 1;
        domain.ptr = Ptr;
    }

    return domain;
}
