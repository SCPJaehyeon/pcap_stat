#include "pcap_stat.h"
using namespace std;

void Usage(char* argv[]){
    cout << "example:) " << argv[0] << " [File_name]" << endl;
}

int show_menu(char* argv[]){
    int select;
    cout << "Select File : " << argv[1] << endl;
    cout << "- EndPoint" << endl;
    cout << "\t 1. Ethernet(not yet)" << endl;
    cout << "\t 2. IPv4" << endl;
    cout << "- Conversation" << endl;
    cout << "\t 3. Ethernet(not yet)" << endl;
    cout << "\t 4. IPv4" << endl;
    cout << "Input Number : ";
    cin >> select;
    return select;
}
int main(int argc, char* argv[]){
    if(argc!=2){
        Usage(argv);
        return -1;
    }
    int select = show_menu(argv);
        switch(select){
            case 1:
                cout << "Endpoint - Ethernet" << endl;
                //epether_capture(argv);
                break;
            case 2:
                cout << "Endpoint - IPv4" << endl;
                epip_capture(argv);
                break;
            case 3:
                cout << "Conversation - Ethernet" << endl;
                //conether_capture(argv);
                break;
            case 4:
                cout << "Conversation - IPv4" << endl;
                conip_capture(argv);
                break;
            default:
                cout << "Please Input Number!" << endl;
                break;
        }
}


