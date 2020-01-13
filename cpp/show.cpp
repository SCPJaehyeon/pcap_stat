#include "pcap_stat.h"
using namespace std;

//Print Usage
void Usage(char* argv[]){
    cout << "example:) " << argv[0] << " [File_name]" << endl;
}

//Print Menu
int show_menu(char* argv[]){
    int select;
    cout << "Select File : " << argv[1] << endl;
    cout << "- EndPoint" << endl;
    cout << "\t 1. Ethernet" << endl;
    cout << "\t 2. IPv4" << endl;
    cout << "- Conversation" << endl;
    cout << "\t 3. Ethernet" << endl;
    cout << "\t 4. IPv4" << endl;
    cout << "- Option" << endl;
    cout << "\t 5. Exit" << endl;
    cout << "Input Number : ";
    cin >> select;
    return select;
}
