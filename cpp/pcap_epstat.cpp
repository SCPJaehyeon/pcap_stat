#include "pcap_stat.h"
using namespace std;

//Endpoint-Ethernet
int epether_stat(char* argv[]){
    //Capture
    char* file = argv[1];
    char errbuf[PCAP_ERRBUF_SIZE];
    pcap_t* handle = pcap_open_offline(file,errbuf); // if file : pcap_open_offline
    if (handle == 0) {
      fprintf(stderr, "couldn't open File! %s: %s\n", file, errbuf);
      return -1;
    }
    struct pcap_pkthdr* header;
    const u_char* packet;
    int res = pcap_next_ex(handle, &header, &packet);

    u_int32_t len=0, len2=0;
    u_char ether[6];
    int cnt=0, cnt2=0, i=1;

    //Struct
    struct epetherh senetherh;
    struct epetherh desetherh;
    struct txrx stxrx;

    //Map<struct, struct>
    map<epetherh, txrx> epether;
    map<epetherh, txrx>::iterator epetherit;

    //Analysis
    while(res==1){
        memcpy(&senetherh.MAC, &packet[6],6);
        memcpy(&desetherh.MAC, &packet[0],6);

        stxrx.txc = cnt;
        stxrx.txs = len;
        stxrx.rxc = cnt2;
        stxrx.rxs = len2;
        auto ret = epether.insert(make_pair(senetherh,stxrx));
        auto ret2 = epether.insert(make_pair(desetherh,stxrx));

        //Add addr && Add Tx count,size;
        if(ret.second == false){
            cnt = epether.find(senetherh)->second.txc + 1;
            len = epether.find(senetherh)->second.txs + header->len;
            cnt2 = epether.find(senetherh)->second.rxc;
            len2 = epether.find(senetherh)->second.rxs;
            stxrx.txc = cnt;
            stxrx.txs = len;
            stxrx.rxc = cnt2;
            stxrx.rxs = len2;
            epether[senetherh] = stxrx;
        }else if(ret.second == true){
            cnt = 1;
            cnt2 = 0;
            len = header->len;
            len2 = 0;
            stxrx.txc = cnt;
            stxrx.txs = len;
            stxrx.rxc = cnt2;
            stxrx.rxs = len2;
            epether[senetherh] = stxrx;
        }

        //Add addr && Add Rx count,size;
        if(ret2.second == false){
            cnt = epether.find(desetherh)->second.txc;
            len = epether.find(desetherh)->second.txs;
            cnt2 = epether.find(desetherh)->second.rxc + 1;
            len2 = epether.find(desetherh)->second.rxs + header->len;
            stxrx.txc = cnt;
            stxrx.txs = len;
            stxrx.rxc = cnt2;
            stxrx.rxs = len2;
            epether[desetherh] = stxrx;
        }else if(ret2.second == true){
            cnt = 0;
            cnt2 = 1;
            len = 0;
            len2 = header->len;
            stxrx.txc = cnt;
            stxrx.txs = len;
            stxrx.rxc = cnt2;
            stxrx.rxs = len2;
            epether[desetherh] = stxrx;
        }
        res = pcap_next_ex(handle, &header, &packet);
    }

    //Print
    printf("no MAC \t\t\t txc \t txs \t rxc \t rxs \n");
    printf("============================================================\n");
    for(epetherit = epether.begin();epetherit != epether.end();epetherit++){
        memcpy(ether, &epetherit->first, 6);
        printf("%d ",i);
        printf("%02x:%02x:%02x:%02x:%02x:%02x \t : ",ether[0],ether[1],ether[2],ether[3],ether[4],ether[5]);
        printf("%d \t%d \t%d \t%d \n",epetherit->second.txc,epetherit->second.txs,epetherit->second.rxc,epetherit->second.rxs);
        i++;
    }
    printf("============================================================\n");

    //Close
    pcap_close(handle);
    return 1;
}



//Endpoint-IPv4
int epip_stat(char* argv[]){
    //Capture
    char* file = argv[1];
    char errbuf[PCAP_ERRBUF_SIZE];
    pcap_t* handle = pcap_open_offline(file,errbuf); // if file : pcap_open_offline
    if (handle == 0) {
      fprintf(stderr, "couldn't open File! %s: %s\n", file, errbuf);
      return -1;
    }
    struct pcap_pkthdr* header;
    const u_char* packet;
    int res = pcap_next_ex(handle, &header, &packet);

    u_int32_t sip, dip, len=0, len2=0;
    u_int8_t ip[4];
    int cnt=0, cnt2=0, i=1;

    //IPv4 Check
    int ipv4cmp = test_ipv4cmp(&packet[12]);

    //Struct
    struct txrx stxrx;

    //Map<u_int32_t, struct>
    map<u_int32_t, txrx> epip;
    map<u_int32_t, txrx>::iterator epipit;

    //Analysis
    while(res==1){
        if(ipv4cmp == 1){
            memcpy(&sip, &packet[26],4);
            memcpy(&dip, &packet[30],4);

            stxrx.txc = cnt;
            stxrx.txs = len;
            stxrx.rxc = cnt2;
            stxrx.rxs = len2;
            auto ret = epip.insert(make_pair(sip,stxrx));
            auto ret2 = epip.insert(make_pair(dip,stxrx));

            //Add addr && Add Tx count,size;
            if(ret.second == false){
                cnt = epip.find(sip)->second.txc + 1;
                len = epip.find(sip)->second.txs + header->len;
                cnt2 = epip.find(sip)->second.rxc;
                len2 = epip.find(sip)->second.rxs;
                stxrx.txc = cnt;
                stxrx.txs = len;
                stxrx.rxc = cnt2;
                stxrx.rxs = len2;
                epip[sip] = stxrx;
            }else if(ret.second == true){
                cnt = 1;
                cnt2 = 0;
                len = header->len;
                len2 = 0;
                stxrx.txc = cnt;
                stxrx.txs = len;
                stxrx.rxc = cnt2;
                stxrx.rxs = len2;
                epip[sip] = stxrx;
            }

            //Add addr && Add Rx count,size;
            if(ret2.second == false){
                cnt = epip.find(dip)->second.txc;
                len = epip.find(dip)->second.txs;
                cnt2 = epip.find(dip)->second.rxc + 1;
                len2 = epip.find(dip)->second.rxs + header->len;
                stxrx.txc = cnt;
                stxrx.txs = len;
                stxrx.rxc = cnt2;
                stxrx.rxs = len2;
                epip[dip] = stxrx;
            }else if(ret2.second == true){
                cnt = 0;
                cnt2 = 1;
                len = 0;
                len2 = header->len;
                stxrx.txc = cnt;
                stxrx.txs = len;
                stxrx.rxc = cnt2;
                stxrx.rxs = len2;
                epip[dip] = stxrx;
            }
        }
        res = pcap_next_ex(handle, &header, &packet);
        ipv4cmp = test_ipv4cmp(&packet[12]);
    }

    //Print
    printf("no IP \t\t\t txc \t txs \t rxc \t rxs \n");
    printf("============================================================\n");
    for(epipit = epip.begin();epipit != epip.end();epipit++){
        memcpy(ip, &epipit->first, sizeof(epipit->first));
        printf("%d ",i);
        printf("%d.%d.%d.%d \t : ",ip[0],ip[1],ip[2],ip[3]);
        printf("%d \t%d \t%d \t%d \n",epipit->second.txc,epipit->second.txs,epipit->second.rxc,epipit->second.rxs);
        i++;
    }
    printf("============================================================\n");

    //Close
    pcap_close(handle);
    return 1;
}



//IPv4 Check
int test_ipv4cmp(const u_char *cmp){
    if(cmp[0]+cmp[1] == 0x0008 || cmp[0]+cmp[1] == 0xDD08){
        return 1;
    }
    else {
        return 0;
    }
}
