//Kachan Rostyslav xkacha02
//ISA 2024

#include "ProcessDNSSections.h"
/// @brief Prints the DNS record type based on the type code
/// @param type Type code of the DNS record
void selectRecordType(uint16_t type) {
    switch (type) {
        case A:
            cout << "A";
            break;
        case NS:
            cout << "NS";
            break;
        case CNAME:
            cout << "CNAME";
            break;
        case SOA:
            cout << "SOA";
            break;
        case MX:
            cout << "MX";
            break;
        case AAAA:
            cout << "AAAA";
            break;
        case SRV:
            cout << "SRV";
            break;

    }
}
/// @brief Prints the DNS class based on the class code
/// @param Class Class code of the DNS record
void selectClass(uint16_t Class) {
    switch(Class) {
        case IN:
            cout << "IN";
            break;
        case CS:
            cout << "CS";
            break;
        case CH:
            cout << "CH";
            break;
        case HS:
            cout << "HS";
            break;
    }
}
/// @brief Processes DNS answer, authority, and additional sections
/// @param Count Number of records in the section
/// @param Ptr Current pointer in the DNS packet dataafter removing the trailing dot
/// @param end_hdr Pointer to the start of DNS packet
/// @param section Section type (ANS, AUTH, ADD)
/// @return Updated pointer after processing the section
unsigned char* processDNSSections(int Count, unsigned char* Ptr, unsigned char* end_hdr, int section) {

    if(section == 1){

        cout << "\n[Answer Section]\n";
    }
    else if (section ==2){
        cout << "\n[Authority Section]\n";
    }
    else{
        cout << "\n[Additional Section]\n";
    }
    for (int i = 0; i < Count; ++i) {

        hlp domain;

        domain = getDomain(end_hdr, Ptr);
        Ptr = domain.ptr;

        uint16_t type = ntohs(*(uint16_t *) Ptr);
        Ptr += 2;

        uint16_t classCode = ntohs(*(uint16_t *) Ptr);
        Ptr += 2;

        uint32_t ttl = ntohl(*(uint32_t *) Ptr);
        Ptr += 4;

        uint16_t rdlength = ntohs(*(uint16_t *) Ptr);
        Ptr += 2;
        if (type != A && type != NS && type != CNAME && type != SOA && type != MX && type != AAAA && type != SRV) {
            cout << "UNKNOWN type of record" << endl;
            Ptr += rdlength;
            continue;
        }
        cout << domain.name << " " << std::dec << ttl << " ";
        selectClass(classCode);
        cout << " ";
        selectRecordType(type);
        cout << " ";
        addDomain(domain.name);

        hlp rdata;
        if (type == 1) {
            for (int j = 0; j < rdlength; ++j) {
                rdata.name += std::to_string(Ptr[j]);
                if (j < rdlength - 1) {
                    rdata.name += ".";
                }
            }
            cout << rdata.name << endl;
            addDomainToIP(domain.name, rdata.name);
            Ptr += rdlength;
        } else if (type == 2) {
            rdata = getDomain(end_hdr, Ptr);
            cout << rdata.name << endl;
            addDomain(rdata.name);
            Ptr = rdata.ptr;
        } else if (type == 5) {
            rdata = getDomain(end_hdr, Ptr);
            cout << rdata.name << endl;
            addDomain(rdata.name);
            Ptr = rdata.ptr;
        } else if (type == 6) {
            hlp mnameResult = getDomain(end_hdr, Ptr);
            Ptr = mnameResult.ptr;

            cout << mnameResult.name << " ";
            addDomain(mnameResult.name);
            hlp rnameResult = getDomain(end_hdr, Ptr);
            cout << rnameResult.name << " ";

            Ptr = rnameResult.ptr;


            uint32_t serial = ntohl(*(uint32_t *) Ptr);
            Ptr += 4;

            uint32_t refresh = ntohl(*(uint32_t *) Ptr);
            Ptr += 4;

            uint32_t retry = ntohl(*(uint32_t *) Ptr);
            Ptr += 4;

            uint32_t expire = ntohl(*(uint32_t *) Ptr);
            Ptr += 4;

            uint32_t minimum = ntohl(*(uint32_t *) Ptr);
            Ptr += 4;
            cout << std::dec << serial << " " << std::dec << refresh << " " << std::dec << retry << " " << std::dec
                 << expire << " " << std::dec << minimum << endl;

        } else if (type == 15) {
            uint16_t preference = ntohs(*(uint16_t *) Ptr);
            Ptr += 2;


            hlp exchangeResult = getDomain(end_hdr, Ptr);
            cout << std::dec << preference << " " << exchangeResult.name << endl;
            addDomain(exchangeResult.name);
            Ptr = exchangeResult.ptr;


        } else if (type == 28) {
            std::string ipv6Address;


            char buffer[INET6_ADDRSTRLEN];
            inet_ntop(AF_INET6, Ptr, buffer, INET6_ADDRSTRLEN);
            ipv6Address = buffer;


            Ptr += 16;
            std::cout << ipv6Address << std::endl;
            addDomainToIP(domain.name, ipv6Address);
        } else if (type == 33) {

            uint16_t priority = ntohs(*(uint16_t *) Ptr);
            Ptr += 2;

            uint16_t weight = ntohs(*(uint16_t *) Ptr);
            Ptr += 2;

            uint16_t port = ntohs(*(uint16_t *) Ptr);
            Ptr += 2;

            hlp targetResult = getDomain(end_hdr, Ptr);
            cout << std::dec << priority << " " << std::dec << weight << " " << std::dec << port << " "
                 << targetResult.name << " " << endl;
            addDomain(targetResult.name);
            Ptr = targetResult.ptr;
        }

    }
    return Ptr;
}

/// @brief Processes DNS question section, extracting domain and query details
/// @param questionCount Number of questions in the DNS query
/// @param lastPtr Pointer to the current position in the DNS data
/// @param end_hdr Pointer to the start of DNS packet
/// @return Updated pointer after processing the question section
unsigned char* processDNSQuestions(int questionCount, unsigned char* lastPtr, unsigned char* end_hdr) {
    unsigned char* ptr = lastPtr;


    for (int i = 0; i < questionCount; ++i) {
        hlp domain = getDomain(end_hdr, ptr);

        int qsize = domain.size;
        qsize += 4;
        ptr = domain.ptr;

        uint16_t qtype = ntohs(*(uint16_t*)ptr);
        ptr += 2;
        uint16_t qclass = ntohs(*(uint16_t*)ptr);
        ptr += 2;
        std::cout << "\n[Question Section]\n";
        if (qtype != A && qtype != NS && qtype != CNAME && qtype != SOA && qtype != MX && qtype != AAAA && qtype != SRV) {
            cout << "UNKNOWN type of record" << endl;
            continue;
        }
        addDomain(domain.name);


        std::cout << domain.name << " ";
        selectClass(qclass);
        std::cout << " ";
        selectRecordType(qtype);
        cout << endl;

    }
    return ptr;
}