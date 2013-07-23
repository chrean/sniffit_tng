/*
 * Generic includes
 */
#include <string.h>
#include <unistd.h>
#include <stdio.h>
#include <stdlib.h>
#include <errno.h>
#include <netdb.h>
#include <getopt.h>

/*
 * System includes
 */

#include <signal.h>
#include <sys/ioctl.h>
#include <sys/socket.h>
#include <sys/types.h>

/*
 * Network includes
 */
#include <net/if.h>
#include <arpa/inet.h>
#include <linux/ip.h>
#include <linux/tcp.h>
#include <linux/udp.h>
#include <linux/icmp.h>
#include <linux/kernel.h>
#include <netinet/if_ether.h>
#include <netinet/in.h>

#include <linux/byteorder/little_endian.h>

enum {
  IPPROTO_CHAOS = 16,
  IPPROTO_SRP = 119
};

enum {
  ETH_P_LLDP = 0x88CC
};

int sock_ioctl;
int fd;
int addr_len;

char buffer[1500]; // 1500 is the standard MTU for ethernet
char src_ip[16];
char dst_ip[16];
char *payload_tcp;
char *payload_ip;

struct ifreq            ifr;
struct ethhdr           *ethernet       = (struct ethhdr *)&buffer[0];
struct iphdr            *ip             = (struct iphdr *)&buffer[sizeof(struct ethhdr)];
struct tcphdr           *tcp;
u_char                  *payload;
struct udphdr           *udp;
struct icmphdr          *icmp;
struct sockaddr         from;
struct sockaddr_in      sin_in;

/*struct iphdr          *payload_ip     = (struct iphdr *)&payload[0];*/

int checkFileAccess(const char* path);
void unpackIP();
int isValidIp4 (const char *str);

void end() {
  ifr.ifr_flags &=~ IFF_PROMISC;        // no more promiscuous mode
  ioctl(sock_ioctl, SIOCSIFFLAGS, &ifr);
  close(sock_ioctl);
  exit(0);
}

/*
 * Simply prints out the usage of this software
 */
void print_usage(const char* exeName) {
  printf("\nUsage: sniffit_tng -i <device> [-l logfile]\n\n");
}

int main(int agc,char *agv[]) {

  char payloadBuffer[1500];
  char *logFilename;
  int option = 0;

  (void) signal(SIGINT, end); // Intercept CTRL+C and calls end()

  if (geteuid ()) {
    fprintf (stderr, "Must be root to run this program\n");
    exit(1);
  }

  if (agc < 2) {
    print_usage(agv[0]);
    exit(1);
  }

  while ((option = getopt(agc, agv, "i:l:")) != -1) {
    switch (option) {
    case 'i':
      memset(&ifr, 0, sizeof(ifr));
      strncpy(ifr.ifr_name, optarg, sizeof(ifr.ifr_name));
      break;
    case 'l':
      logFilename = (char*)malloc(strlen(optarg));
      strncpy(logFilename, optarg, strlen(optarg));

      if (!checkFileAccess(logFilename)) {
        exit(EXIT_FAILURE);
      }
      break;
    default:
      print_usage(agv[0]);
      exit(EXIT_FAILURE);
    }
  }

  if (strlen(ifr.ifr_name) == 0) {
    print_usage(agv[0]);
    exit(EXIT_FAILURE);
  }

  if ((sock_ioctl = socket(PF_INET, SOCK_DGRAM, 0)) < 0) {
    perror("Error calling socket()");
    exit(1);
  }

  addr_len = sizeof(struct sockaddr);

  printf("\nSniffing on device : ");
  printf("%s\n\n", ifr.ifr_name);

  if ((ioctl(sock_ioctl, SIOCGIFFLAGS, &ifr)) < 0) {
    fprintf(stderr, "%s", "ioctl() error, device probably does not exist or is not accessible.\n\n");
    exit(1);
  }

  ifr.ifr_flags |= IFF_PROMISC;
  ioctl(sock_ioctl, SIOCSIFFLAGS, &ifr);

  strncpy(from.sa_data, agv[1], sizeof(from.sa_data));
  if ((fd = socket(PF_PACKET, SOCK_RAW, htons(ETH_P_ALL))) < 0) {
    perror("socket() error");
    exit(1);
  }

  while(1) {
    recvfrom(fd, buffer, sizeof(buffer), 0, (struct sockaddr *)&from,&addr_len);

    switch (__be16_to_cpu(ethernet->h_proto)) {
    case ETH_P_IP:
      unpackIP();
      break;
    case ETH_P_ARP:
      break;
    case ETH_P_IPV6:
      break;
    case ETH_P_RARP:
      break;
    case ETH_P_LLDP:
      printf("LLDP Packet detected.\n");
      break;
    default:
      printf("Another Ethertype detected: %04X\n", __be16_to_cpu(ethernet->h_proto));
      break;

    }
  }
}

void unpackIP() {

  switch (ip->protocol) {
  case IPPROTO_CHAOS:
    printf("Chaos Packet detected\n");
    printf("Eth Protocol: %04X\n", __be16_to_cpu(ethernet->h_proto));
    break;
  case IPPROTO_SRP:
    printf("Spectralink packet detected\n");
    printf("Eth Protocol: %04X\n", __be16_to_cpu(ethernet->h_proto));
    break;
  case IPPROTO_IDP:
    printf("Xerox IDP protocol detected\n");
    printf("Eth Protocol: %04X\n", __be16_to_cpu(ethernet->h_proto));
    break;
  case IPPROTO_GRE:
    // This is GRE, I don't care for now
    // printf("GRE detected\n");
    break;
  case IPPROTO_ESP:
    // I don't care for ESP as well
    break;
  case IPPROTO_IGMP:
    // We expect some IGMP
    break;
  case IPPROTO_TCP:
    //printf("\n----IP----\n");
    tcp = (struct tcphdr *)&buffer[sizeof(struct ethhdr) + sizeof(struct iphdr)];

    sin_in.sin_addr.s_addr = ip->daddr;
    sprintf(src_ip, "%s", inet_ntoa(sin_in.sin_addr));
    sin_in.sin_addr.s_addr = ip->saddr;
    sprintf(dst_ip, "%s", inet_ntoa(sin_in.sin_addr));

    // I'll print the packets only if src or dst are 0.
    // Not smart, should check for valid IPs and will do in a next release
    //if (dst_ip[0] != '0' || src_ip[0] != '0') break;

    if (isValidIp4(src_ip) && isValidIp4(dst_ip)) break;

    printf("IP source : %s\n", dst_ip);
    printf("IP destination : %s\n", src_ip);



    printf("\n----- IP Header -----\n");
    printf("IP: Header length    : %d bytes\n", ip->ihl*4);
    printf("IP: Version          : %d  \n", ip->version);
    printf("IP: Total length     : %d \n", ntohs(ip->tot_len));
    printf("IP: Identification   : %d \n", ntohs(ip->id));
    printf("IP: Flags            : %.2x\n", (unsigned char)((ip->frag_off)>>12));
    printf("IP: Fragment offset  : %d  \n", ntohs(ip->frag_off) & 0x0FFF);
    printf("IP: Time to live     : %d  \n", ip->ttl);
    printf("IP: Protocol         : %d  \n", ip->protocol);

    printf("----TCP----\n");

    printf("Source Port: %u\n", ntohs(tcp->source));
    printf("Destination Port: %u\n", ntohs(tcp->dest));
    printf("Sequence number : %u\n", ntohl(tcp->seq));
    printf("ACK-SEQ : %u\n", ntohl(tcp->ack_seq));
    printf("SYN : %u\n", tcp->syn);
    printf("ACK : %u\n", tcp->ack);
    printf("FIN : %u\n", tcp->fin);
    printf("RST : %u\n", tcp->fin);
    printf("ttl : %u\n", ip->ttl);
    payload = (u_char *)((char *)tcp + sizeof(struct tcphdr));
    printf("payload: %s\n", payload);
    break;
  case IPPROTO_UDP:
    udp = (struct udphdr *)&buffer[sizeof(struct ethhdr) + sizeof(struct iphdr)];

    if (ntohs(udp->source) != 0) break;
    printf("----UDP----\n");
    printf("\n----IP----\n");
    sin_in.sin_addr.s_addr = ip->daddr;
    printf("Destination IP: %s\n", inet_ntoa(sin_in.sin_addr));
    sin_in.sin_addr.s_addr = ip->saddr;
    printf("Source IP: %s\n", inet_ntoa(sin_in.sin_addr));

    printf("Source Port: %u\n", ntohs(udp->source));
    printf("Destination Port: %u\n", ntohs(udp->dest));
    break;
  case IPPROTO_ICMP:
    // Don't want to print ICMP packets
    if(1) break;

    printf("\n----IP----\n");
    sin_in.sin_addr.s_addr = ip->daddr;
    printf("Destination IP: %s\n", inet_ntoa(sin_in.sin_addr));
    sin_in.sin_addr.s_addr = ip->saddr;

    printf("----ICMP----\n");
    icmp = (struct icmphdr *)&buffer[sizeof(struct ethhdr) + sizeof(struct iphdr)];
    printf("Source IP : %s\n", inet_ntoa(sin_in.sin_addr));
    printf("type : %u\n", icmp->type);
    printf("code : %u\n", icmp->code);
    break;
  default:
    tcp = (struct tcphdr *)&buffer[sizeof(struct ethhdr) + sizeof(struct iphdr)];
    printf("\n---- Unknown protocol      ----\n");
    sin_in.sin_addr.s_addr = ip->daddr;
    printf("Destination IP : %s\n", inet_ntoa(sin_in.sin_addr));
    sin_in.sin_addr.s_addr = ip->saddr;
    printf("Source IP : %s \n", inet_ntoa(sin_in.sin_addr));
    printf("IP: Protocol         : %d  \n", ip->protocol);

    payload_tcp = (char*)malloc(sizeof(struct tcphdr));
    payload_ip = (char*)malloc(sizeof(struct iphdr));
    //  strncpy(payload_buffer, buffer,
    payload = (u_char *)((char *)tcp + sizeof(struct tcphdr));
    printf("payload: %s\n\n\n", payload);

    break;
  }

}

int isValidIp4 (const char *str) {
  int segs = 0;   /* Segment count. */
  int chcnt = 0;  /* Character count within segment. */
  int accum = 0;  /* Accumulator for segment. */

  /* Catch NULL pointer. */

  if (str == NULL)
    return 0;

  /* Process every character in string. */

  while (*str != '\0') {
    /* Segment changeover. */

    if (*str == '.') {
      /* Must have some digits in segment. */

      if (chcnt == 0)
        return 0;

      /* Limit number of segments. */

      if (++segs == 4)
        return 0;

      /* Reset segment values and restart loop. */

      chcnt = accum = 0;
      str++;
      continue;
    }
    /* Check numeric. */

    if ((*str < '0') || (*str > '9'))
      return 0;

    /* Accumulate and check segment. */

    if ((accum = accum * 10 + *str - '0') > 255)
      return 0;

    /* Advance other segment specific stuff and continue loop. */

    chcnt++;
    str++;
  }

  /* Check enough segments and enough characters in last segment. */

  if (segs != 3)
    return 0;

  if (chcnt == 0)
    return 0;

  /* Address okay. */

  return 1;
}

/*
 * Checks whether the file exists, is readable and writable
 */

int checkFileAccess(const char* path) {

  int rval;

  if(!strlen(path)) {
    return 0;
  }

  rval = access (path, F_OK);
  if (rval == 0)
    printf ("%s exists\n", path);
  else {
    /* Check file existence. */
    if (errno == ENOENT)
      printf ("%s does not exist\n", path);
    /*
     * In this case I should create the file, if the path is readable and writable
     */
    /* Check file access. */
    else if (errno == EACCES)
      printf ("%s is not accessible\n", path);
    return 0;
  }
  /* Check read access. */
  rval = access (path, R_OK);
  if (rval == 0)
    printf ("%s is readable\n", path);
  else
    printf ("%s is not readable (access denied)\n", path);
  /* Check write access. */
  rval = access (path, W_OK);
  if (rval == 0)
    printf ("%s is writable\n", path);
  else if (errno == EACCES)
    printf ("%s is not writable (access denied)\n", path);
  else if (errno == EROFS)
    printf ("%s is not writable (read-only filesystem)\n", path);
  return 0;
}
