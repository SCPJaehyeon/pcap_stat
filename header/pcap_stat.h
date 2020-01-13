#pragma once
#ifndef PCAP_STAT_H
#define PCAP_STAT_H

#include <iostream>
#include <cstdio>
#include <stdint.h>
#include <arpa/inet.h>
#include <cstring>
#include <pcap/pcap.h>
#include <map>

//Ethernet struct - Endpoint
struct epetherh {
    u_char MAC[6];
    bool operator<(const epetherh& omac) const{
        if(this->MAC[0]+this->MAC[1]+this->MAC[2]+this->MAC[3]+this->MAC[4]+this->MAC[5] < omac.MAC[0]+omac.MAC[1]+omac.MAC[2]+omac.MAC[3]+omac.MAC[4]+omac.MAC[5]){
            return true;
        }
        return false;
    }
};

//Ethernet struct - Conversation
struct conetherh {
    u_char MACa[6];
    u_char MACb[6];
    bool operator<(const conetherh& omac) const{
        if(this->MACb[0]+this->MACb[1]+this->MACb[2]+this->MACa[3]+this->MACa[4]+this->MACa[5] < omac.MACb[0]+omac.MACb[1]+omac.MACb[2]+omac.MACa[3]+omac.MACa[4]+omac.MACa[5]){
            return true;
        }

        return false;
    }
};

//TxCount, TxSize, RxCount, RxSize struct
struct txrx{
    int txc;
    u_int32_t txs;
    int rxc;
    u_int32_t rxs;
};

//Show
void Usage(char* argv[]);
int show_menu(char* argv[]);

//IPv4 Check
int test_ipv4cmp(const u_char *cmp);

//Analysis
int epip_stat(char* argv[]);
int epether_stat(char* argv[]);
int conip_stat(char* argv[]);
int conether_stat(char* argv[]);

#endif
