//Kachan Rostyslav xkacha02
//ISA 2024
#include <iostream>
#include <unistd.h>
#include <string>
using namespace std;

int main(int argc, char* argv[]) {
    int opt;
    std::cout << "Hello, World!" << std::endl;
    bool interface_provided = false;
    bool pcapfile_provided = false;
    bool full_mode = false;
    string interface;
    string pcapfile;
    string domainsfile;
    string translationsfile;

    // Parsing command line arguments
    while ((opt = getopt(argc, argv, "i:p:vd:t:")) != -1) {
        switch (opt) {
            case 'i':
                if (interface_provided) {
                    cerr << "ERR: Option -i specified more than once.\n";
                    return EXIT_FAILURE;
                }
                if (optarg[0] == '-') { // Check if optarg is another option
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
                if (optarg[0] == '-') { // Check if optarg is another option
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
                if (optarg[0] == '-') { // Check if optarg is another option
                    cerr << "ERR: Domainsfile not specified after -d\n";
                    return EXIT_FAILURE;
                }
                domainsfile = optarg;
                break;
            case 't':
                if (optarg[0] == '-') { // Check if optarg is another option
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

    //Check if parameters are provided
    if (!interface_provided && !pcapfile_provided) {
        cerr
                << "ERR: Interface or pcapfile  were not specified!\tUsage: ./dns-monitor (-i <interface> | -p <pcapfile>)\n";
        return EXIT_FAILURE;
    }
    if (interface_provided && pcapfile_provided) {
        cerr
                << "ERR: You cant use this 2 options! You have to choose only one)\tUsage: ./dns-monitor (-i <interface> | -p <pcapfile>)\n";
        return EXIT_FAILURE;
    }
    return 0;
}
