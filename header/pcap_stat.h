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
        return MAC[5] < omac.MAC[5];
    }
};

//Ethernet struct - Conversation
struct conetherh {
    u_char MACa[6];
    u_char MACb[6];
    bool operator<(const conetherh& omac) const{
        return MACa[5] < omac.MACa[5];
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
