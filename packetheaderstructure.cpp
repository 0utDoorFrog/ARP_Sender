#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <stdint.h>
#include <math.h>


#include "packetheaderstructure.h"
#include "pcap.h"

void getMacAddress(const char * interface, unsigned char * dst)
{
    char command[100] = "";

    sprintf(command, "ifconfig %s | grep ether > result.txt", interface); // make command
    system(command); // save the result to result.txt

    FILE * fp = fopen("./result.txt","r"); // open file

    char readbuffer[32] ="";
    fgets(readbuffer,sizeof(readbuffer),fp); // read data

    char macAddress[17] = "";

    for(int i=0;i<=16;i++)
        macAddress[i]=readbuffer[i+14]; // read only Mac Data

    strcpy((char *)dst, macAddress); // return Mac Data

    fclose(fp);
}

long long ipConvertInt(char * ipString) // covert ip to int(big endian)
{
    long long ret=0;
    char * oct;

    for (int i = 3; i>=0;i--){
        oct = strtok(ipString, ".");
        ret += pow(256., i) * atoi(oct);
        ipString = nullptr;
    }
    return ret;
}

const unsigned char * macConvertArray(const unsigned char * macString)
{
    unsigned char iMac[6];
    unsigned int macMiddler[6];
    int i;
    sscanf( (const char *)macString, "%02x:%02x:%02x:%02x:%02x:%02x", &macMiddler[0], &macMiddler[1], &macMiddler[2], &macMiddler[3], &macMiddler[4], &macMiddler[5]);
    for(i=0;i<6;i++)
       iMac[i] =(unsigned char ) macMiddler[i];

    return (const unsigned char * )iMac;

}

unsigned char * generatePacket1(unsigned const char * srcMac, long long senderIP, long long targetIP)
{
    struct packetData * packetdata;

    packetdata = (struct packetData *)malloc(sizeof(struct packetData));


    for (int i=0;i<6;i++)
    {
        packetdata->ethernetheader.srcMac[i] = srcMac[i];
    }

    for (int i=0;i<6;i++)
    {
        packetdata->ethernetheader.dstMac[i] = 0xFF;
    }

    packetdata->ethernetheader.type = (0x06<<8) + 0x08;

    packetdata->arpheader.hardwareType = 0x0100;
    packetdata->arpheader.protocolType = (0x00<<8) + 0x08;
    packetdata->arpheader.hardwareSize = 6;
    packetdata->arpheader.ProtocolSize = 4;
    packetdata->arpheader.opcode = (ARP_REQUEST << 8) + 0x00;

    for(int i=0;i<6;i++)
    {

        packetdata->arpheader.senderMac[i] = srcMac[i];
    }

    packetdata->arpheader.senderIP[0] = (((senderIP>>8)>>8)>>8);
    packetdata->arpheader.senderIP[1] = ((senderIP>>8)>>8) & 0xFF;
    packetdata->arpheader.senderIP[2] = (senderIP>>8) & 0xFF;
    packetdata->arpheader.senderIP[3] = senderIP & 0xFF;

    for(int i=0;i<6;i++)
    {
        packetdata->arpheader.targetMac[i] = 0x00;
    }


    packetdata->arpheader.targetIP[0] = (((targetIP>>8)>>8)>>8);
    packetdata->arpheader.targetIP[1] = ((targetIP>>8)>>8) & 0xFF;
    packetdata->arpheader.targetIP[2] = (targetIP>>8) & 0xFF;
    packetdata->arpheader.targetIP[3] = targetIP & 0xFF;

    return (unsigned char *)packetdata;
}


unsigned char * generatePacket2(unsigned const char * srcMac ,unsigned const char * dstMac, long long senderIP, long long targetIP)
{
    struct packetData * packetdata;

    packetdata = (struct packetData *)malloc(sizeof(struct packetData));

    for (int i=0;i<6;i++)
    {
        packetdata->ethernetheader.srcMac[i] = srcMac[i];
    }


    for (int i=0;i<6;i++)
    {
        packetdata->ethernetheader.dstMac[i] = dstMac[i];
    }

    packetdata->ethernetheader.type = (0x06<<8) + 0x08;

    packetdata->arpheader.hardwareType = 0x0100;
    packetdata->arpheader.protocolType = (0x00<<8) + 0x08;
    packetdata->arpheader.hardwareSize = 6;
    packetdata->arpheader.ProtocolSize = 4;
    packetdata->arpheader.opcode = (ARP_REPLY << 8) + 0x00;


    packetdata->arpheader.senderMac[0] = 0xca;
    packetdata->arpheader.senderMac[1] = 0xff;
    packetdata->arpheader.senderMac[2] = 0xee;
    packetdata->arpheader.senderMac[3] = 0xca;
    packetdata->arpheader.senderMac[4] = 0xff;
    packetdata->arpheader.senderMac[5] = 0xee;

    packetdata->arpheader.senderIP[0] = (((senderIP>>8)>>8)>>8);
    packetdata->arpheader.senderIP[1] = ((senderIP>>8)>>8) & 0xFF;
    packetdata->arpheader.senderIP[2] = (senderIP>>8) & 0xFF;
    packetdata->arpheader.senderIP[3] = senderIP & 0xFF;

    for(int i=0;i<6;i++)
    {
        packetdata->arpheader.targetMac[i] = dstMac[i];
    }


    packetdata->arpheader.targetIP[0] = (((targetIP>>8)>>8)>>8);
    packetdata->arpheader.targetIP[1] = ((targetIP>>8)>>8) & 0xFF;
    packetdata->arpheader.targetIP[2] = (targetIP>>8) & 0xFF;
    packetdata->arpheader.targetIP[3] = targetIP & 0xFF;

    return (unsigned char *)packetdata;
}
