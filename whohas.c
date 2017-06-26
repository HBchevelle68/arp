#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <errno.h>

#include <unistd.h>
#include <sys/types.h>
#include <sys/socket.h>
#include <arpa/inet.h>
#include <netinet/udp.h>
#include <netinet/ip.h>
#include <net/if.h>
#include <net/if_ether.h>
#include <linux/if_packet.h> 
#include <net/ethernet.h>
#include <netdb.h>
#include <sys/ioctl.h>
#include <bits/ioctls.h>




void usage();


int main(int argc, char* argv[]){

    int rsfd;
    const int on = 1;
    char *temp_csum, *ifname, *dst_ip, *src_ip;
    struct sockaddr_in sin;
    struct udpchk uchk;
    struct addrinfo hints, *res;
    void* tmp;


    if(argc < 1) {
        usage();
        return 0;
    }

    ifname = malloc(20);
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


    // For getaddrinfo().
    memset (&hints, 0, sizeof (struct addrinfo));
    hints.ai_family = AF_INET;
    hints.ai_socktype = SOCK_STREAM;
    hints.ai_flags = hints.ai_flags | AI_CANONNAME;

    // Resolve dst_ip using getaddrinfo().
    if (getaddrinfo (dst_ip, NULL, &hints, &res) != 0) {
        perror("getaddrinfo() error: ");
        exit (EXIT_FAILURE);
    }
    //convert from binary to text string
    ipv4 = (struct sockaddr_in *) res->ai_addr;
    tmp = &(ipv4->sin_addr);
    if (inet_ntop (AF_INET, tmp, dst_ip, INET_ADDRSTRLEN) == NULL) {
         perror("inet)_ntop() error");
        exit (EXIT_FAILURE);
    }
    freeaddrinfo (res);





    /* FILL WITH ARP FIELDS*/











    memset(&sin, 0, sizeof(struct sockaddr_in));
    sin.sin_family = AF_INET;
    sin.sin_addr.s_addr = iph->ip_dst.s_addr;

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

    for(int count = 1; count <= pcktcount; count++){
        if(sendto(rsfd, dgram, size, 0, (struct sockaddr*) &sin, sizeof(struct sockaddr)) < 0){
            perror("sendto() failed");
            exit(EXIT_FAILURE);
        }
        else {
            printf("\rSent UDP dgram #%d", count);
        }
        
    }
    printf("\n");
    free(ifname);
    free(dst_ip);
    free(src_ip);

    close(rsfd);
    
    return 0;
}



void usage(){
    printf("Usage: sudo ./whohas\n");
}
