#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <errno.h>
#include <unistd.h>

#include <sys/types.h>
#include <sys/socket.h>
#include <arpa/inet.h>
#include <netinet/ip.h>
#include <net/if.h>
#include <linux/if_packet.h> 
#include <linux/if_ether.h>
#include <net/ethernet.h>
#include <netdb.h>
#include <sys/ioctl.h>
#include <bits/ioctls.h>

//As per include/uapi/linux/if_arp.h
struct _arphdr {
    uint16_t    ar_hrd;     /* format of hardware address */
    uint16_t    ar_pro;     /* format of protocol address */
    uint8_t     ar_hln;     /* length of hardware address */
    uint8_t     ar_pln;     /* length of protocol address */
    uint16_t    ar_op;      /* ARP opcode (command)       */
    uint8_t     ar_sha[6];  /* sender hardware address    */
    uint8_t     ar_sip[4];  /* sender IP address          */
    uint8_t     ar_tha[6];  /* target hardware address    */
    uint8_t     ar_tip[4];  /* target IP address          */
};


void usage();


int main(int argc, char* argv[]){

    int rsfd;
    const int on = 1;
    char *ifname, *dst_ip, *src_ip, *src_mac, *dst_mac;
    char aframe[IP_MAXPACKET];            
    struct sockaddr_in sin, *ipv4;
    struct sockaddr_ll ll_dev;
    struct addrinfo hints, *res;
    struct ethhdr *ehdr;
    struct _arphdr *ahdr;
    void* tmp;


    if(argc < 3) {
        usage();
        return 0;
    }

    ifname = malloc(20);
    src_mac = malloc(6);
    dst_mac = malloc(6); 
    dst_ip = malloc(INET_ADDRSTRLEN);
    src_ip = malloc(INET_ADDRSTRLEN);

    strcpy(ifname, argv[1]);
    strcpy (src_ip, argv[2]);
    strcpy (dst_ip, argv[3]);
    
    //create raw socket
    if ((rsfd = socket(AF_INET, SOCK_RAW, IPPROTO_RAW)) < 0) {
        perror("socket() raw socket creation failed ");
        exit(EXIT_FAILURE);
    }

    //grab interface index
    struct ifreq ifr;
    memset(&ifr, 0, sizeof(ifr));
    snprintf (ifr.ifr_name, sizeof(ifr.ifr_name), "%s", ifname);
    if(ioctl(rsfd, SIOCGIFHWADDR, &ifr) < 0){
        perror("HWADDR ioctl() error: ");
        exit(EXIT_FAILURE);
    }
    close(rsfd);
    printf ("Index for interface %s is %i\n", ifname, ifr.ifr_ifindex);

    //get my mac 
    memcpy(src_mac, ifr.ifr_hwaddr.sa_data, 6);
    //set destination to broadcast addr 
    memcpy(dst_mac, 0xff, 6);

    //Get interface index for sockaddr_ll
    memset (&ll_dev, 0, sizeof (ll_dev));
    if ((ll_dev.sll_ifindex = if_nametoindex(ifname)) == 0) {
        perror ("if_nametoindex() failed to obtain interface index ");
        exit(EXIT_FAILURE);
    }
    printf("Index for interface %s is %i\n", ifname, ll_dev.sll_ifindex);


    // For getaddrinfo().
    memset (&hints, 0, sizeof (struct addrinfo));
    hints.ai_family = AF_INET;
    hints.ai_socktype = SOCK_STREAM;
    hints.ai_flags = hints.ai_flags | AI_CANONNAME; //canonical name

    // Resolve dst_ip using getaddrinfo().
    if (getaddrinfo (dst_ip, NULL, &hints, &res) != 0) {
        perror("getaddrinfo() error: ");
        exit(EXIT_FAILURE);
    }
    //convert from binary to text string
    ipv4 = (struct sockaddr_in *) res->ai_addr;
    tmp = &(ipv4->sin_addr);
    if (inet_ntop(AF_INET, tmp, dst_ip, INET_ADDRSTRLEN) == NULL) {
         perror("inet)_ntop() error");
        exit(EXIT_FAILURE);
    }
    freeaddrinfo (res);

    // Fill out sockaddr_ll.
    ll_dev.sll_family = AF_PACKET;
    memcpy (ll_dev.sll_addr, src_mac, 6);
    ll_dev.sll_halen = 6;

    memset(aframe, 0, sizeof(aframe));


    ehdr = (struct ethhdr*) aframe;
    ahdr = (struct _arphdr*) (aframe + sizeof(struct ethhdr));

    

    


    //create raw socket
    if ((rsfd = socket(AF_INET, SOCK_RAW, IPPROTO_RAW)) < 0) {
        perror("socket() raw socket creation failed ");
        exit(EXIT_FAILURE);
    }

    // Set flag so socket expects IPv4 header.
    if (setsockopt (rsfd, IPPROTO_IP, IP_HDRINCL, &on, sizeof(on)) < 0) {
        perror ("setsockopt() failed to set IP_HDRINCL: ");
        exit(EXIT_FAILURE);
    }

    // Bind socket to ifr index.
    if (setsockopt (rsfd, SOL_SOCKET, SO_BINDTODEVICE, &ifr, sizeof(ifr)) < 0) {
        perror ("setsockopt() failed to bind to interface: ");
        exit(EXIT_FAILURE);
    }

    printf("Sending...\n");

   
    if(sendto(rsfd, aframe, size, 0, (struct sockaddr*) &sin, sizeof(struct sockaddr)) < 0){
        perror("sendto() failed");
        exit(EXIT_FAILURE);
    }
    else {
        printf("Sent ARP Request \n");
    }
        

    free(ifname);
    free(dst_ip);
    free(src_ip);

    close(rsfd);
    
    return 0;
}



void usage(){
    printf("Usage: sudo ./whohas\n");
}
