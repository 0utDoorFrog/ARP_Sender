#pragma once

#include <stdio.h>
#include <stdlib.h>
#include <string.h>

#define ARP_REQUEST  0x1
#define ARP_REPLY    0x2
#define RARP_REQUEST 0x3
#define RARP_REPLY   0x4

struct ethernetHeader
{
    u_int8_t dstMac[6]; // target mac
    u_int8_t srcMac[6]; // sender mac
    u_int16_t type;     // ARP = 0806
};

struct arpHeader
{
    u_int16_t hardwareType; // default = 1
    u_int16_t protocolType; // default = 0800
    u_int8_t hardwareSize;  // default = 6
    u_int8_t ProtocolSize;  // default = 4
    u_int16_t opcode;
    u_int8_t senderMac[6];
    u_int8_t senderIP[4];
    u_int8_t targetMac[6];
    u_int8_t targetIP[4];
};

struct packetData
{
    struct ethernetHeader ethernetheader;
    struct arpHeader arpheader;
};

long long ipConvertInt(char * ipString);

void getMacAddress(const char * interface, unsigned char * dst);

const unsigned char * macConvertArray(const unsigned char * macString);

unsigned char * generatePacket1(unsigned const char * srcMac, long long senderIP, long long targetIP);

unsigned char * generatePacket2(unsigned const char * srcMac, unsigned const char * dstMac, long long senderIP, long long targetIP);
