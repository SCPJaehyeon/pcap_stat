#pragma once
#ifndef PCAP_STAT_H
#define PCAP_STAT_H
#define ETYPE 0x0608


#include <iostream>
#include <cstdio>
#include <stdint.h>
#include <arpa/inet.h>
#include <cstring>
#include <pcap/pcap.h>
#include <map>



/*struct etherh { //Ethernet header
    u_char MAC[6];
    bool operator<(const etherh& omac) const{
        if(MAC[0] < omac.MAC[0]){
            return true;
        }else{
            return false;
        }
    }
};
struct conetherh { //Ethernet header
    u_char MACa[6];
    u_char MACb[6];
    bool operator<(const conetherh& omac) const{
        if(MACa[0] < omac.MACa[0] || MACb[0] < omac.MACb[0]){
            return MACa[0] < omac.MACa[0];
        }else{
            return false;
        }
    }
};*/

struct txrx{
    int txc;
    u_int32_t txs;
    int rxc;
    u_int32_t rxs;
};

int epip_capture(char* argv[]);
int epether_capture(char* argv[]);
int conip_capture(char* argv[]);
int conether_capture(char* argv[]);

#endif
