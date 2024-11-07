//Kachan Rostyslav xkacha02
//ISA 2024
#include <iostream>
#include <unistd.h>
#include <string>
#include <pcap.h>
#include <netinet/ip.h>   // For IP header
#include <netinet/udp.h>  // For UDP header
#include <arpa/inet.h>    // For inet_ntoa
#include <ctime>          // For time formatting
using namespace std;

bool full_mode = false;

struct dnshdr {
    uint16_t id;
    uint16_t flags;
    uint16_t q_count;
    uint16_t ans_count;
    uint16_t auth_count;
    uint16_t add_count;
};

enum DnsRecordType {
    A = 1,
    NS = 2,
    CNAME = 5,
    SOA = 6,
    MX = 15,
    AAAA = 28,
    SRV = 33
};

enum DnsClass {
    IN = 1,
    CS = 2,
    CH = 3,
    HS = 4
};
struct hlp{
    int size;
    unsigned char* ptr;
    string name;
};



void selectRecordType(uint16_t qtype) {
    switch (qtype) {
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
        default:
            return;
    }
}

void selectClass(uint16_t qclass) {
    switch(qclass) {
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
//hlp getDomainOleg(unsigned char* startPtr, unsigned char* Ptr) {
//    hlp result;
//    result.name = "";
//    result.size = 0;
//    bool isCompressed = false;
//    int safetyCounter = 0;  // Захист від нескінченних циклів
//
//    while (*Ptr != 0) {
//        if (safetyCounter++ > 100) {  // Захист від можливих нескінченних циклів
//            std::cerr << "ERR: Possible infinite loop or corrupted packet" << std::endl;
//            result.ptr = nullptr;
//            return result;
//        }
//
//        uint8_t labelLength = *Ptr;
//
//        // Перевірка на стиснення (два старші біти 11)
//        if ((labelLength & 0xC0) == 0xC0) {
//            // Отримуємо 14-бітове значення зміщення для компресії
//            uint16_t offset = ((labelLength & 0x3F) << 8) | *(Ptr + 1);
//            Ptr = startPtr + offset;  // Переходимо за новим зміщенням
//
//            if (!isCompressed) {
//                // Зберігаємо місце після стисненого вказівника для повернення ptr
//                result.ptr = Ptr + 2;
//            }
//            isCompressed = true;
//            continue;
//        }
//
//        // Якщо це звичайна мітка, обробляємо її
//        result.size += labelLength + 1;  // Додаємо розмір мітки плюс один для довжини
//        Ptr++;  // Переміщаємося вперед після байту довжини
//        for (int j = 0; j < labelLength; ++j) {
//            result.name += *Ptr;  // Додаємо символи мітки до імені
//            Ptr++;
//        }
//        result.name += '.';  // Додаємо крапку після мітки
//    }
//
//    Ptr++; // Пропускаємо нульовий байт, що позначає кінець QNAME
//
//    // Видаляємо зайву крапку, якщо ім'я не порожнє
//    if (!result.name.empty() && result.name.back() == '.') {
//        result.name.pop_back();
//    }
//
//    // Повертаємо запам'ятоване значення ptr, якщо було стиснення
//    result.ptr = isCompressed ? result.ptr : Ptr;
//    return result;
//}
hlp getDomain(unsigned char* Ptr){
    //unsigned char* my_ptr = Ptr;
    hlp a;
    a.size = 0;
    a.name;
    while (*Ptr != 0) {

        a.size += *Ptr + 1;
        // Додаємо розмір мітки плюс байт довжини
        int labelLength = *Ptr;

        cout << "Label Length: " << labelLength << endl;
        if (labelLength > 63) {
            cerr << "ERR: Invalid label length in NAME" << endl;
            EXIT_FAILURE;
        }
        Ptr++;
        for (int j = 0; j < labelLength; ++j) {
            //cout << "Adress: " << *Ptr;
            //cout << "NAME SYMBOLS: " << *Ptr;
            a.name += *Ptr;
            Ptr++;
        }
        a.name += '.';
    }

    Ptr++; // Пропускаємо нульовий байт, що позначає кінець QNAME
    a.ptr = Ptr;
    a.size+=1;
   // cout << "Size " << a.size << endl;
//    cout  << "DOMAIN NAME: " << a.name << " \n";
    return a;
}


hlp getDomainSecond(unsigned char* startPtr, unsigned char* Ptr) {
    hlp a;
    a.size = 0;
    a.name = "";

    hlp additional_struct_to_identif_comp;
    additional_struct_to_identif_comp.size  = 0;
    additional_struct_to_identif_comp.name  = "";
    unsigned char* originalPtr = Ptr;
    bool jumped = false;
    bool compression_on_start = false;
    int safetyCounter = 0;

    while (*Ptr != 0) {
        if (safetyCounter++ > 100) {
            throw std::runtime_error("Помилка: можливий некоректний пакет або нескінченний цикл");
        }

        if ((*Ptr & 0xC0) == 0xC0) { // Перевірка на компресію (два старші біти встановлені в 1)
            if(a.size == 0){
                compression_on_start = true;
            }
            additional_struct_to_identif_comp.size = a.size;
            if (!jumped) {
                a.size += 2; // Додаємо 2 байти для компресованої адреси
            }

            int offset = ((*Ptr & 0x3F) << 8) | *(Ptr + 1); // Отримуємо зміщення
            Ptr = startPtr + offset; // Переходимо за вказаним зміщенням
            jumped = true; // Позначаємо, що було стиснення
        } else {
            int labelLength = *Ptr; // Довжина мітки
            if (labelLength > 63) {
                throw std::runtime_error("ERR: Invalid label length in NAME");
            }

            Ptr++; // Переходимо до символів мітки
            a.size += labelLength + 1; // Додаємо розмір мітки та байт довжини

            // Додаємо символи мітки до імені
            for (int j = 0; j < labelLength; ++j) {
                a.name += *Ptr;
                Ptr++;
            }
            a.name += '.'; // Додаємо крапку після мітки
        }
    }
    if(compression_on_start){
        a.ptr = originalPtr + 2;
        return a;
    }
    if (!jumped) {
        Ptr++; // Пропускаємо нульовий байт, якщо не було стрибка
        a.size += 1; // Додаємо нульовий байт до розміру
    }


    // Зберігаємо вказівник на наступну позицію після доменного імені
    // Якщо було стиснення, повертаємося до оригінальної позиції + 2 байти (компресійний вказівник)
    a.ptr = jumped ? originalPtr + additional_struct_to_identif_comp.size + 2 : Ptr;

    std::cout << "Size: " << a.size << std::endl;
    return a;
}





unsigned char* processDNSAnswer(int Count, unsigned char* Ptr, unsigned char* end_hdr) {
    // Початковий вказівник на DNS Answers

    for (int i = 0; i < Count; ++i) {
        //std::string name;
        hlp b;
//        // Обробка імені з урахуванням компресії
//        if ((*ptr & 0xC0) == 0xC0) { // Перевірка на стиснення
//
//            uint16_t offset = ((*ptr & 0x3F) << 8) | *(ptr + 1); // Обчислюємо зміщення
//            unsigned char* compressedPtr = end_hdr + offset; // Переходимо до місця зі стисненим іменем
//            b = getDomain(compressedPtr); // Розпаковуємо стиснене ім'я
//            name = b.name;
//            ptr += 2; // Пропускаємо 2 байти компресії
//        } else {
//             b = getDomain(ptr); // Обробляємо звичайне ім'я
//            if (b.ptr == nullptr) {
//                std::cerr << "Error processing domain name in Answer section" << std::endl;
//                return nullptr;
//            }
//            name = b.name;
//            ptr = b.ptr; // Оновлюємо ptr після обробки імені
//        }
        b = getDomainSecond(end_hdr,Ptr);
        Ptr = b.ptr;
        // Читаємо TYPE (2 байти)
        uint16_t type = ntohs(*(uint16_t*)Ptr);
        Ptr += 2;

        // Читаємо CLASS (2 байти)
        uint16_t classCode = ntohs(*(uint16_t*)Ptr);
        Ptr += 2;

        // Читаємо TTL (4 байти)
        uint32_t ttl = ntohl(*(uint32_t*)Ptr);
        Ptr += 4;

        // Читаємо RDLENGTH (2 байти)
        uint16_t rdlength = ntohs(*(uint16_t*)Ptr);
        Ptr += 2;

        // Пропускаємо RDATA (rdlength байтів)

//        hlp rdata ;
//        hlp rdata;
//        if(type == 1) {
//            for (int j = 0; j < rdlength; ++j) {
//                rdata.name += std::to_string(ptr[j]);
//                if (j < rdlength - 1) {
//                    rdata.name += ".";
//                }
//            }
//            ptr += rdlength;
//        }
            hlp rdata;
            cout << "TYPE: " << type << endl;
            if(type == 1) {
            for (int j = 0; j < rdlength; ++j) {
                rdata.name += std::to_string(Ptr[j]);
                if (j < rdlength - 1) {
                    rdata.name += ".";
                }
            }
                Ptr += rdlength;
            }
            else if(type == 2){
                rdata = getDomainSecond(end_hdr,Ptr);
                Ptr+=rdlength;
            }
            else if(type == 5){// Перевірка на стиснення

                    rdata = getDomainSecond(end_hdr,Ptr);
                    //Ptr+=rdlength;
                    Ptr = rdata.ptr;
            }
            else if(type == 6){
                hlp mnameResult = getDomainSecond(end_hdr, Ptr); // MNAME
                std::string mname = mnameResult.name;
                Ptr = mnameResult.ptr;

                hlp rnameResult = getDomainSecond(end_hdr, Ptr); // RNAME
                std::string rname = rnameResult.name;
                Ptr = rnameResult.ptr;
                //Ptr =  Ptr + (rdlength-20-mnameResult.size);

                // Читаємо числові значення
                uint32_t serial = ntohl(*(uint32_t*)Ptr);
                Ptr += 4;

                uint32_t refresh = ntohl(*(uint32_t*)Ptr);
                Ptr += 4;

                uint32_t retry = ntohl(*(uint32_t*)Ptr);
                Ptr += 4;

                uint32_t expire = ntohl(*(uint32_t*)Ptr);
                Ptr += 4;

                uint32_t minimum = ntohl(*(uint32_t*)Ptr);
                Ptr += 4;
                std::cout << "SOA Record: MNAME=" << mname << ", RNAME=" << rname
                          << ", Serial=" << serial << ", Refresh=" << refresh
                          << ", Retry=" << retry << ", Expire=" << expire
                          << ", Minimum TTL=" << minimum << std::endl;
            }
            else if(type == 15){
                uint16_t preference = ntohs(*(uint16_t*)Ptr);
                Ptr += 2;

                // Викликаємо getDomain для розпаковки Exchange як доменного імені
                hlp exchangeResult = getDomainSecond(end_hdr, Ptr);
                std::string exchange = exchangeResult.name;
                Ptr += rdlength - 2;
                std::cout << "MX Record: Preference=" << preference << ", Exchange=" << exchange << std::endl;

            }
            else if(type == 28){
                std::string ipv6Address;

                // Зчитуємо 16 байт IPv6 адреси
                char buffer[INET6_ADDRSTRLEN];
                inet_ntop(AF_INET6, Ptr, buffer, INET6_ADDRSTRLEN);
                ipv6Address = buffer;

                // Пропускаємо RDATA після обробки
                Ptr += 16;
                std::cout << "AAAA Record: IPv6 Address=" << ipv6Address << std::endl;
            }
            else if(type == 33){
                // Зчитуємо поле Priority (2 байти)
                uint16_t priority = ntohs(*(uint16_t*)Ptr);
                Ptr += 2;

                // Зчитуємо поле Weight (2 байти)
                uint16_t weight = ntohs(*(uint16_t*)Ptr);
                Ptr += 2;

                // Зчитуємо поле Port (2 байти)
                uint16_t port = ntohs(*(uint16_t*)Ptr);
                Ptr += 2;

                // Викликаємо getDomain для розпаковки Target як доменного імені
                hlp targetResult = getDomainSecond(end_hdr, Ptr);
                std::string target = targetResult.name;
                Ptr +=rdlength-6 ;
                std::cout << "SRV Record: Priority=" << priority << ", Weight=" << weight
                          << ", Port=" << port << ", Target=" << target << std::endl;
            }
            else{
                Ptr+=rdlength;
            }





        // Виводимо інформацію про запис
        std::cout << "\n[Answers Section]\n";
        std::cout << "Answer NAME: " << b.name << " " << ttl << " ";
        selectClass(classCode);
        std::cout << " ";
        selectRecordType(type);
        //std::cout << endl;
        //std::cout << "\nSize: " << qsize << " байтів" << std::endl;
        cout << " RDATA " << rdata.name << endl;
    }

    return Ptr; // Повертаємо вказівник на кінець оброблених записів
}


unsigned char* processDNSQuestions(int questionCount, unsigned char* startPtr) {
    unsigned char* ptr = startPtr; // Початковий вказівник на DNS Questions

    // Обробляємо кожне питання
    for (int i = 0; i < questionCount; ++i) {
        hlp b = getDomain(ptr);
        //std::string qname = "";z
        int qsize = b.size;

        // Парсимо QNAME

        qsize += 4; // Додаємо 5 байтів для QTYPE і QCLASS
        ptr = b.ptr;
        // Парсимо QTYPE і QCLASS
        uint16_t qtype = ntohs(*(uint16_t*)ptr);
        ptr += 2;
        uint16_t qclass = ntohs(*(uint16_t*)ptr);
        ptr += 2;

        // Виводимо інформацію про питання
        std::cout << "\n[Question Section]\n";
        std::cout << "QNAME: " << b.name << " ";
        selectClass(qclass);
        std::cout << " ";
        selectRecordType(qtype);
        std::cout << "\nSize: " << qsize << " байтів" << std::endl;
    }

    // Повертаємо вказівник на кінець розділу DNS Questions
    return ptr;
}


void packetHandler(u_char* userData, const struct pcap_pkthdr* pkthdr, const u_char* packet) {
    char timeString[64];
    std::time_t rawtime = pkthdr->ts.tv_sec;
    struct tm* timeinfo = localtime(&rawtime);
    strftime(timeString, sizeof(timeString), "%Y-%m-%d %H:%M:%S", timeinfo);

    const struct ip* ipHeader = (struct ip*)(packet + 14);
    int ipHeaderLen = ipHeader->ip_hl * 4;

    std::string srcIP = inet_ntoa(ipHeader->ip_src);
    std::string destIP = inet_ntoa(ipHeader->ip_dst);

    const struct udphdr* udpHeader = (struct udphdr*)(packet + 14 + ipHeaderLen);

    uint16_t srcPort = ntohs(udpHeader->uh_sport);
    uint16_t dstPort = ntohs(udpHeader->uh_dport);

    const struct dnshdr* dnsHeader = (struct dnshdr*)(packet + 14 + ipHeaderLen + sizeof(struct udphdr));

    uint16_t ID= ntohs(dnsHeader->id);
    uint16_t flags = ntohs(dnsHeader->flags);
    uint16_t opcode = (flags >> 11) & 0xF;
    uint16_t aa = (flags >> 10) & 0x1;
    uint16_t tc = (flags >> 9) & 0x1;
    uint16_t rd = (flags >> 8) & 0x1;
    uint16_t ra = (flags >> 7) & 0x1;
    uint16_t ad = (flags >> 5) & 0x1;
    uint16_t cd = (flags >> 4) & 0x1;
    uint16_t rcode = (flags >> 3) & 0xF;
    bool isResponse = (flags >> 15) & 0x1;
    char qrType = isResponse ? 'R' : 'Q';

    uint16_t qCount = ntohs(dnsHeader->q_count);
    uint16_t ansCount = ntohs(dnsHeader->ans_count);
    uint16_t authCount = ntohs(dnsHeader->auth_count);
    uint16_t addCount = ntohs(dnsHeader->add_count);

    unsigned char* ptr_end_hdr = (unsigned char*)dnsHeader + sizeof(dnshdr);
    unsigned char* ptr_Header = (unsigned char*)dnsHeader;
    unsigned char* ptr = ptr_end_hdr;
    int qsize = 0;
    if (qCount != 0) {

        ptr = processDNSQuestions(qCount,ptr_end_hdr);
//        std::string qname = "";
//        while (*ptr != 0) {
//            qsize += *ptr + 1;
//            int labelLength = *ptr;
//            ptr++;
//            for (int i = 0; i < labelLength; ++i) {
//                qname += *ptr;
//                ptr++;
//            }
//            qname += '.';
//        }
//        qsize += 5;
//        ptr++;
//
//        uint16_t qtype = ntohs(*(uint16_t*)ptr);
//        ptr += 2;
//        uint16_t qclass = ntohs(*(uint16_t*)ptr);
//        ptr += 2;
//        cout << "\n[Question Section]\n";
//        cout << "QNAME is " << qname << " ";
//        selectClass(qclass);
//        cout << " ";
//        selectRecordType(qtype);
//        cout << endl;
//        cout << "Size " << qsize << endl;
    }

    if (ansCount != 0) {
        ptr = processDNSAnswer(ansCount,ptr, ptr_Header);
    }
//    if(authCount != 0){
//        ptr = processDNSAnswer(authCount,ptr, ptr_Header);
//    }
//    if(addCount != 0){
//        ptr = processDNSAnswer(addCount,ptr, ptr_Header);
//    }
    if (full_mode) {
        cout << "Timestamp: " << timeString << endl;
        cout << "SrcIP: " << srcIP << endl;
        cout << "DstIP: " << destIP << endl;
        cout << "SrcPort: UDP/" << std::dec << srcPort << endl;
        cout << "DstPort: UDP/" << std::dec << dstPort << endl;
        cout << "Identifier: 0x" << std::hex << ID << endl;
        cout << "Flags: QR=" << int(isResponse) << endl;
        cout << "Flags: OPCODE=" << opcode << endl;
        cout << "Flags: AA=" << aa << endl;
        cout << "Flags: TC=" << tc << endl;
        cout << "Flags: RD=" << rd << endl;
        cout << "Flags: RA=" << ra << endl;
        cout << "Flags: AD=" << ad << endl;
        cout << "Flags: CD=" << cd << endl;
        cout << "Flags: RCODE=" << rcode << endl;
        cout << "$$$$$$$$$$$$$$$$$$$$$$$$$$$$$$$$$$$$$$$$$$$$$$$$$$$$$$$44" << endl;
    } else {
        std::cout << timeString << " " << srcIP << " -> " << destIP << " (" << qrType << " " << qCount << "/" << ansCount << "/" << authCount << "/" << addCount << ")" << std::endl;
    }
}

void captureFromInterface(const std::string& interface) {
    char errbuf[PCAP_ERRBUF_SIZE];
    pcap_t* handle = pcap_open_live(interface.c_str(), BUFSIZ, 1, 1000, errbuf);
    if (handle == nullptr) {
        std::cerr << "Could not open device " << interface << ": " << errbuf << std::endl;
        return;
    }

    struct bpf_program filter;
    if (pcap_compile(handle, &filter, "udp port 53", 0, PCAP_NETMASK_UNKNOWN) == -1) {
        std::cerr << "Could not parse filter: " << pcap_geterr(handle) << std::endl;
        pcap_close(handle);
        return;
    }
    if (pcap_setfilter(handle, &filter) == -1) {
        std::cerr << "Could not install filter: " << pcap_geterr(handle) << std::endl;
        pcap_close(handle);
        return;
    }

    pcap_loop(handle, 0, packetHandler, nullptr);

    pcap_freecode(&filter);
    pcap_close(handle);
}

void captureFromFile(const std::string& pcapfile) {
    char errbuf[PCAP_ERRBUF_SIZE];
    pcap_t* handle = pcap_open_offline(pcapfile.c_str(), errbuf);
    if (handle == nullptr) {
        std::cerr << "Could not open file " << pcapfile << ": " << errbuf << std::endl;
        return;
    }

    struct bpf_program filter;
    if (pcap_compile(handle, &filter, "udp port 53", 0, PCAP_NETMASK_UNKNOWN) == -1) {
        std::cerr << "Could not parse filter: " << pcap_geterr(handle) << std::endl;
        pcap_close(handle);
        return;
    }
    if (pcap_setfilter(handle, &filter) == -1) {
        std::cerr << "Could not install filter: " << pcap_geterr(handle) << std::endl;
        pcap_close(handle);
        return;
    }

    pcap_loop(handle, 0, packetHandler, nullptr);

    pcap_freecode(&filter);
    pcap_close(handle);
}

int main(int argc, char* argv[]) {

    int opt;
    std::cout << "Hello, World!" << std::endl;
    bool interface_provided = false;
    bool pcapfile_provided = false;

    string interface;
    string pcapfile;
    string domainsfile;
    string translationsfile;

    while ((opt = getopt(argc, argv, "i:p:vd:t:")) != -1) {
        switch (opt) {
            case 'i':
                if (interface_provided) {
                    cerr << "ERR: Option -i specified more than once.\n";
                    return EXIT_FAILURE;
                }
                if (optarg[0] == '-') {
                    cerr << "ERR: Interface not specified after -i\n";
                    return EXIT_FAILURE;
                }
                interface = optarg;
                interface_provided = true;
                break;
            case 'p':
                if (pcapfile_provided) {
                    cerr << "ERR: Option -p specified more than once.\n";
                    return EXIT_FAILURE;
                }
                if (optarg[0] == '-') {
                    cerr << "ERR: Pcapfile not specified after -p\n";
                    return EXIT_FAILURE;
                }
                pcapfile = optarg;
                pcapfile_provided = true;
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
                cout << "-v Full information about dns packet\n";
                cout << "-v - verbose mode: complete listing of DNS message details;\n";
                cout << "-d <domainsfile> - the name of the domain name file\n";
                cout << "-t <translationsfile> - the name of the domain name to IP translation file\n";
                return EXIT_FAILURE;
        }
    }

    if (!interface_provided && !pcapfile_provided) {
        cerr << "ERR: Interface or pcapfile were not specified!\tUsage: ./dns-monitor (-i <interface> | -p <pcapfile>)\n";
        return EXIT_FAILURE;
    }
    if (interface_provided && pcapfile_provided) {
        cerr << "ERR: You cant use this 2 options! You have to choose only one)\tUsage: ./dns-monitor (-i <interface> | -p <pcapfile>)\n";
        return EXIT_FAILURE;
    }

    if (!interface.empty()) {
        captureFromInterface(interface);
    } else if (!pcapfile.empty()) {
        captureFromFile(pcapfile);
    }
    return 0;
}

