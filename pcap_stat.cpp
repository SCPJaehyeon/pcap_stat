#include "pcap_stat.h"
using namespace std;

int test_ipcmp(const u_char *cmp){
    int ip = 0;
    if(cmp[0]+cmp[1] == 0x0008 || cmp[0]+cmp[1] == 0xDD08){
        ip = 1;
        return ip;
    }
    else {
        ip = 0;
        return ip;
    }
}

int epip_capture(char* argv[]){
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
    u_int32_t sip;
    u_int32_t dip;
    u_int8_t ip[4];
    int cnt=0, cnt2=0;
    u_int32_t len=0, len2=0;
    int ipv4cmp = test_ipcmp(&packet[12]);
    struct txrx stxrx;
    map<u_int32_t, txrx> epip;
    map<u_int32_t, txrx>::iterator epipit;
    while(res==1){
        if(ipv4cmp){
        memcpy(&sip, &packet[26],4);
        memcpy(&dip, &packet[30],4);

        stxrx.txc = cnt;
        stxrx.txs = len;
        stxrx.rxc = cnt2;
        stxrx.rxs = len2;
        auto ret = epip.insert(make_pair(sip,stxrx));
        auto ret2 = epip.insert(make_pair(dip,stxrx));
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
        }}
        res = pcap_next_ex(handle, &header, &packet);
        ipv4cmp = test_ipcmp(&packet[12]);
    }
    int i = 1;
    printf("no IP \t\t txc \t txs \t rxc \t rxs \n");
    printf("============================================================\n");
    for(epipit = epip.begin();epipit != epip.end();epipit++){
        memcpy(ip, &epipit->first, sizeof(epipit->first));
        printf("%d ",i);
        printf("%d.%d.%d.%d \t : ",ip[0],ip[1],ip[2],ip[3]);
        printf("%d \t",epipit->second.txc);
        printf("%d \t",epipit->second.txs);
        printf("%d \t",epipit->second.rxc);
        printf("%d \n",epipit->second.rxs);
        i++;
    }
    printf("============================================================\n");
    pcap_close(handle);
    return 1;
}
/*
int epether_capture(char* argv[]){
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
    //u_char sether[6];
    //u_char dether[6];
    u_char ether[6];
    int cnt=0, cnt2=0;
    u_int32_t len=0, len2=0;
    struct etherh senetherh;
    struct etherh desetherh;
    struct txrx stxrx;
    map<etherh, txrx> epether;
    map<etherh, txrx>::iterator epetherit;
    while(res==1){
        memcpy(&senetherh.MAC, &packet[6],6);
        memcpy(&desetherh.MAC, &packet[0],6);
        stxrx.txc = cnt;
        stxrx.txs = len;
        stxrx.rxc = cnt2;
        stxrx.rxs = len2;
        auto ret = epether.insert(make_pair(senetherh,stxrx));
        auto ret2 = epether.insert(make_pair(desetherh,stxrx));
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
    int i = 1;
    printf("no MAC \t\t txc \t txs \t rxc \t rxs \n");
    printf("============================================================\n");
    for(epetherit = epether.begin();epetherit != epether.end();epetherit++){
        memcpy(ether, &epetherit->first, sizeof(epetherit->first));
        printf("%d ",i);
        printf("%02x:%02x:%02x:%02x:%02x:%02x \t : ",ether[0],ether[1],ether[2],ether[3],ether[4],ether[5]);
        printf("%d \t",epetherit->second.txc);
        printf("%d \t",epetherit->second.txs);
        printf("%d \t",epetherit->second.rxc);
        printf("%d \n",epetherit->second.rxs);
        i++;
    }
    printf("============================================================\n");
    pcap_close(handle);
    return 1;
}*/

int conip_capture(char* argv[]){
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
    u_int64_t sip;
    u_int32_t dip[2], ip3[2];
    u_int64_t dip2, cmpip, dip3;
    u_int8_t ip[8];
    int cnt=0, cnt2=0;
    u_int32_t len=0, len2=0;
    int ipv4cmp = test_ipcmp(&packet[12]);
    struct txrx stxrx;
    map<u_int64_t, txrx> conip;
    map<u_int64_t, txrx>::iterator conipit;
    map<u_int64_t, txrx>::iterator conipit2;
    while(res==1){
        if(ipv4cmp == 1){
            memcpy(&sip, &packet[26],8);
            memcpy(&dip[0], &packet[30],4);
            memcpy(&dip[1],&packet[26],4);
            memcpy(&dip2, &dip[0],8);
            memcpy(&dip3, &packet[26],8);
            stxrx.txc = cnt;
            stxrx.txs = len;
            stxrx.rxc = cnt2;
            stxrx.rxs = len2;
            auto ret = conip.insert(make_pair(sip,stxrx));
            auto ret2 = conip.insert(make_pair(dip2,stxrx));

            if(ret.second == false){
                cnt = conip.find(sip)->second.txc + 1;
                len = conip.find(sip)->second.txs + header->len;
                cnt2 = conip.find(sip)->second.rxc;
                len2 = conip.find(sip)->second.rxs;
                stxrx.txc = cnt;
                stxrx.txs = len;
                stxrx.rxc = cnt2;
                stxrx.rxs = len2;
                conip[sip] = stxrx;
            }else if(ret.second == true){
                cnt = 1;
                len = header->len;
                cnt2 = 0;
                len2 = 0;
                stxrx.txc = cnt;
                stxrx.txs = len;
                stxrx.rxc = cnt2;
                stxrx.rxs = len2;
                conip[sip] = stxrx;
            }
            if(ret2.second == false){
                cnt = conip.find(dip2)->second.txc;
                len = conip.find(dip2)->second.txs;
                cnt2 = conip.find(dip2)->second.rxc + 1;
                len2 = conip.find(dip2)->second.rxs + header->len;
                stxrx.txc = cnt;
                stxrx.txs = len;
                stxrx.rxc = cnt2;
                stxrx.rxs = len2;
                conip[dip2] = stxrx;
                conip.erase(sip);
            }else if(ret2.second == true){
                cnt = 0;
                len = 0;
                cnt2 = 1;
                len2 = header->len;
                stxrx.txc = cnt;
                stxrx.txs = len;
                stxrx.rxc = cnt2;
                stxrx.rxs = len2;
                conip[dip2] = stxrx;
                conip.erase(dip2);
            }
        }
        res = pcap_next_ex(handle, &header, &packet);
        ipv4cmp = test_ipcmp(&packet[12]);
    } 

    int i = 1;
    printf("no AddrA \t\t AddrB \t\t A>Bc \t A>Bs \t B>Ac \t B>As \n");
    printf("============================================================\n");
    for(conipit = conip.begin();conipit != conip.end();conipit++){

        memcpy(&ip, &conipit->first, 8); //for print

        memcpy(&ip3[0], &conipit->first+8,4); //for erase
        memcpy(&ip3[1], &conipit->first,4);
        memcpy(&cmpip, &ip3[0],8);

        printf("%d ",i);
        printf("%d.%d.%d.%d \t\t",ip[0],ip[1],ip[2],ip[3]);
        printf("%d.%d.%d.%d \t : ",ip[4],ip[5],ip[6],ip[7]);
        printf("%d \t",conipit->second.txc);
        printf("%d \t",conipit->second.txs);
        printf("%d \t",conipit->second.rxc);
        printf("%d \n",conipit->second.rxs);
        i++;
    }
    printf("============================================================\n");
    pcap_close(handle);
    return 1;
}
/*
int conether_capture(char* argv[]){
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
    struct conetherh senetherh;
    struct conetherh desetherh;
    struct txrx stxrx;
    u_char ether1[12];
    int cnt=0, cnt2=0;
    u_int32_t len=0, len2=0;
    map<conetherh, txrx> conether;
    map<conetherh, txrx>::iterator conetherit;
    map<conetherh, txrx>::iterator conetherit2;
    while(res==1){
        memcpy(&senetherh.MACa, &packet[6],6);
        memcpy(&senetherh.MACb, &packet[0],6);
        memcpy(&desetherh.MACa, &packet[0],12);

        stxrx.txc = cnt;
        stxrx.txs = len;
        stxrx.rxc = cnt2;
        stxrx.rxs = len2;
        auto ret = conether.insert(make_pair(senetherh,stxrx));
        auto ret2 = conether.insert(make_pair(desetherh,stxrx));
        if(ret.second == false){
            cnt = conether.find(senetherh)->second.txc + 1;
            len = conether.find(senetherh)->second.txs + header->len;
            cnt2 = conether.find(senetherh)->second.rxc;
            len2 = conether.find(senetherh)->second.rxs;
            stxrx.txc = cnt;
            stxrx.txs = len;
            stxrx.rxc = cnt2;
            stxrx.rxs = len2;
            conether[senetherh] = stxrx;
        }else if(ret.second == true){
            cnt = 1;
            cnt2 = 0;
            len = header->len;
            len2 = 0;
            stxrx.txc = cnt;
            stxrx.txs = len;
            stxrx.rxc = cnt2;
            stxrx.rxs = len2;
            conether[senetherh] = stxrx;

        }
        if(ret2.second == false){
            cnt = conether.find(desetherh)->second.txc;
            len = conether.find(desetherh)->second.txs;
            cnt2 = conether.find(desetherh)->second.rxc + 1;
            len2 = conether.find(desetherh)->second.rxs + header->len;
            stxrx.txc = cnt;
            stxrx.txs = len;
            stxrx.rxc = cnt2;
            stxrx.rxs = len2;
            conether[desetherh] = stxrx;
        }else if(ret2.second == true){
            cnt = 0;
            cnt2 = 1;
            len = 0;
            len2 = header->len;
            stxrx.txc = cnt;
            stxrx.txs = len;
            stxrx.rxc = cnt2;
            stxrx.rxs = len2;
            conether[desetherh] = stxrx;
        }
        res = pcap_next_ex(handle, &header, &packet);
    }

    int i = 1;
    printf("no AddrA \t\t AddrB \t A>Bc \t A>Bs \t B>Ac \t B>As \n");
    printf("============================================================\n");
    for(conetherit = conether.begin();conetherit != conether.end();conetherit++){
        memcpy(&ether1, &conetherit->first, 12);
        //memcpy(&ip3[0], &conetherit->first+8,4);
        //memcpy(&ip3[1], &conetherit->first,4);
        //memcpy(&cmpip, &ip3[0],8);


        printf("%d ",i);
        printf("%02x:%02x:%02x:%02x:%02x:%02x \t\t",ether1[0],ether1[1],ether1[2],ether1[3],ether1[4],ether1[5]);
        printf("%02x:%02x:%02x:%02x:%02x:%02x \t : ",ether1[6],ether1[7],ether1[8],ether1[9],ether1[10],ether1[11]);
        printf("%d \t",conetherit->second.txc);
        printf("%d \t",conetherit->second.txs);
        printf("%d \t",conetherit->second.rxc);
        printf("%d \n",conetherit->second.rxs);
        i++;
    }
    printf("============================================================\n");
    pcap_close(handle);
    return 1;
}
*/
