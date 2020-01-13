#include "header/pcap_stat.h"
using namespace std;

//Conversations-Ethernet
int conether_stat(char* argv[]){
    //Capture
    char* file = argv[1];
    char errbuf[PCAP_ERRBUF_SIZE];
    pcap_t* handle = pcap_open_offline(file,errbuf);
    if (handle == 0) {
      fprintf(stderr, "couldn't open File! %s: %s\n", file, errbuf);
      return -1;
    }
    struct pcap_pkthdr* header;
    const u_char* packet;
    int res = pcap_next_ex(handle, &header, &packet);

    u_int32_t len=0, len2=0;
    u_char ether[12];
    int cnt=0, cnt2=0, i=1;

    //Struct
    struct conetherh senetherh;
    struct conetherh desetherh;
    struct txrx stxrx;

    //Map<struct, struct>
    map<conetherh, txrx> conether;
    map<conetherh, txrx>::iterator conetherit;

    //Analysis
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

        //Add addr && Add A>B count,size;
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
            len = header->len;
            cnt2 = 0;
            len2 = 0;
            stxrx.txc = cnt;
            stxrx.txs = len;
            stxrx.rxc = cnt2;
            stxrx.rxs = len2;
            conether[senetherh] = stxrx;
        }

        //Add addr && Add B>A count,size;
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
            conether.erase(senetherh);
        }else if(ret2.second == true){
            cnt = 0;
            len = 0;
            cnt2 = 1;
            len2 = header->len;
            stxrx.txc = cnt;
            stxrx.txs = len;
            stxrx.rxc = cnt2;
            stxrx.rxs = len2;
            conether[desetherh] = stxrx;
            conether.erase(desetherh);
        }
        res = pcap_next_ex(handle, &header, &packet);
    }

    //Print
    printf("no AddrA \t\t\t AddrB \t\t\t A>Bc \t A>Bs \t B>Ac \t B>As \n");
    printf("=========================================================================================\n");
    for(conetherit = conether.begin();conetherit != conether.end();conetherit++){
        memcpy(&ether, &conetherit->first, 12);
        printf("%d ",i);
        printf("%02x:%02x:%02x:%02x:%02x:%02x \t\t",ether[0],ether[1],ether[2],ether[3],ether[4],ether[5]);
        printf("%02x:%02x:%02x:%02x:%02x:%02x \t : ",ether[6],ether[7],ether[8],ether[9],ether[10],ether[11]);
        printf("%d \t%d \t%d \t%d \n",conetherit->second.txc,conetherit->second.txs,conetherit->second.rxc,conetherit->second.rxs);
        i++;
    }
    printf("=========================================================================================\n");

    //Close
    pcap_close(handle);
    return 1;
}



//Conversations-IPv4
int conip_stat(char* argv[]){
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

    u_int64_t sip, dip2;
    u_int32_t len=0, len2=0, dip[2];
    u_int8_t ip[8];
    int cnt=0, cnt2=0, i=1;

    //IPv4 Check
    int ipv4cmp = test_ipv4cmp(&packet[12]);

    //Struct
    struct txrx stxrx;

    //Map<u_int64_t, struct>
    map<u_int64_t, txrx> conip;
    map<u_int64_t, txrx>::iterator conipit;

    //Analysis
    while(res==1){
        if(ipv4cmp == 1){
            memcpy(&sip, &packet[26],8);
            memcpy(&dip[0], &packet[30],4);
            memcpy(&dip[1],&packet[26],4);
            memcpy(&dip2, &dip[0],8);

            stxrx.txc = cnt;
            stxrx.txs = len;
            stxrx.rxc = cnt2;
            stxrx.rxs = len2;
            auto ret = conip.insert(make_pair(sip,stxrx));
            auto ret2 = conip.insert(make_pair(dip2,stxrx));

            //Add addr && Add A>B count,size;
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

            //Add addr && Add B>A count,size;
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
        ipv4cmp = test_ipv4cmp(&packet[12]);
    }

    //Print
    printf("no AddrA \t\t\t AddrB \t\t A>Bc \t A>Bs \t B>Ac \t B>As \n");
    printf("=========================================================================================\n");
    for(conipit = conip.begin();conipit != conip.end();conipit++){
        memcpy(&ip, &conipit->first, 8); //for print
        printf("%d ",i);
        printf("%d.%d.%d.%d \t\t",ip[0],ip[1],ip[2],ip[3]);
        printf("%d.%d.%d.%d \t : ",ip[4],ip[5],ip[6],ip[7]);
        printf("%d \t%d \t%d \t%d \n",conipit->second.txc,conipit->second.txs,conipit->second.rxc,conipit->second.rxs);
        i++;
    }
    printf("=========================================================================================\n");

    //Close
    pcap_close(handle);
    return 1;
}


