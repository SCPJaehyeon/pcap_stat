#include "pcap_stat.h"
using namespace std;

int main(int argc, char* argv[]){
    if(argc!=2){
        Usage(argv);
        return -1;
    }
    while(1){
        int select = show_menu(argv);
        switch(select){
            case 1:
                cout << "Endpoint - Ethernet" << endl;
                epether_stat(argv);
                break;
            case 2:
                cout << "Endpoint - IPv4" << endl;
                epip_stat(argv);
                break;
            case 3:
                cout << "Conversation - Ethernet" << endl;
                conether_stat(argv);
                break;
            case 4:
                cout << "Conversation - IPv4" << endl;
                conip_stat(argv);
                break;
            case 5:
                cout << "Exit" << endl;
                return 0;
            default:
                cout << "Wrong Number!" << endl;
                return 0;
        }
    }
}


