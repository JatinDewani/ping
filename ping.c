#include <stdio.h>
#include <string.h>
#include<arpa/inet.h>
#include <sys/types.h>
#include <sys/socket.h>
#include <stdlib.h>
#include <netinet/ip_icmp.h>
#include <netdb.h>
#include <unistd.h>
#include <time.h>
#include <netinet/in.h>
#include <arpa/inet.h>
#include <math.h>
#include <sys/time.h>
#include <signal.h>
#include <errno.h>
#include <netinet/ip6.h>
#include <netinet/icmp6.h>
#include <stddef.h>

/* A simple CLI application which imitates ping.
 * Repeatedly sends ICMP echo messages to the IP address/
 * hostname passed in through the command line.
 * It sends packets in a set interval indefinitely if 
 * the c option (defined below) is not specified.
 * It reports the RTT and packet loss for each packet sent.
 *
 * Can be invoked as follows:
 * sudo ./ping.x <hostname/IP> [options]
 * - IP address passed in can be either IPv4 or IPv6.
 * - Need superuser privileges to run this application, as it uses
 *   Raw sockets to send ICMP messages.
 *
 * options:
 *      t: set ttl for outgoing packets. Can only be whole numbers >= 0
 *      
 *      c: set a fixed number of packets to be sent, should be > 1.
 *      
 *      i: change the regular interval in which the packets are sent.
 *          Intervals can only be set in seconds, in whole numbers.
 *          if i=0, the regular intervals are removed and packets
 *          are flooded as fast as the system can handle. The default 
 *          value for interval is 1s.
 */

typedef struct{
    struct sockaddr_in addr;
    struct sockaddr_in6 addr6;
    int which;
} Addr;

Addr *setAddr(Addr *sa, char *str);
uint16_t checksum(uint16_t *buf, int l);
void v4(int sock, struct sockaddr_in sa, struct sockaddr_in ra, 
        int c, int signum, sigset_t alarm_sig, int interval);
void printP(double rtt, int num, int lost, int rec, int sent); 
void v6(int sock, struct sockaddr_in6 sa, struct sockaddr_in6 ra, 
        int c, int signum, sigset_t alarm_sig, int interval); 

void miss(int signum){}

int main(int argc, char *argv[]){
    if (argc == 1) {
        fprintf(stderr, "Please provide hostname/IP to ping.\n");
        exit(-1);
    }
    int opt;
    int ttl = -1, interval = -1, c = -1;
    opterr = 0;
    Addr sa;
    int sock;
    struct timeval tv;
    struct itimerval timer;
    int signum = 0;
    sigset_t alarm_sig;

    bzero(&sa, sizeof(sa));

    //parsing the options
    while((opt = getopt(argc, argv, ":t:c:i:")) != -1)
    {
        switch(opt)
        {
            case 't':
                ttl = atoi(optarg);
                break;
            case 'c':
                c = atoi(optarg);
                break;
            case 'i':
                interval = atoi(optarg);
                break;
            case ':':
                fprintf(stderr, "option needs a value.\n");
                exit(-1);
                break;
            case '?':
                fprintf(stderr, "unknown option.\n");
                exit(-1);
                break;
        }
    }
    
    //setting timer for interval (if specified)
    if (interval == -1) {
        timer.it_interval.tv_sec = timer.it_value.tv_sec = 1;
        timer.it_interval.tv_usec = timer.it_value.tv_usec = 0;

        tv.tv_sec = 1;
        tv.tv_usec = 0;
    } else if (interval == 0) {
        tv.tv_sec = 1;
        tv.tv_usec = 0;
    }
    else {
        timer.it_interval.tv_sec = timer.it_value.tv_sec = interval;
        timer.it_interval.tv_usec = timer.it_value.tv_usec = 0;

        tv.tv_sec = interval;
        tv.tv_usec = 0;
    }

    sa = *setAddr(&sa, argv[optind]);

    if (sa.which == 0)
        sock = socket(AF_INET, SOCK_RAW, IPPROTO_ICMP);
    else
        sock = socket(AF_INET6, SOCK_RAW, IPPROTO_ICMPV6);

    if (sock <= 0) {
        fprintf(stderr, "Raw Socket creation failure, make sure you have superuser privileges.\n");
        exit(-1);
    }
    //fprintf(stderr, "%d", sock);

    if(ttl == -1)
        ttl = 64;
    setsockopt(sock, SOL_IP, IP_TTL, &ttl, sizeof(ttl));
    setsockopt(sock, SOL_SOCKET, SO_RCVTIMEO, (const struct timeval*)&tv, sizeof(tv)); 

    if (interval != 0) {
        setitimer(ITIMER_REAL, &timer, 0);      
        sigemptyset(&alarm_sig);
        sigaddset(&alarm_sig, SIGALRM);
        signal(SIGALRM, miss);
    }

    //handling the IP version appropriately
    if (sa.which == 0) {
        struct sockaddr_in ra;
        bzero(&ra, sizeof(ra));
        v4(sock, sa.addr, ra, c, signum, alarm_sig, interval);
    } else {
        //perror("here");
        struct sockaddr_in6 ra;
        bzero(&ra, sizeof(ra));
        v6(sock, sa.addr6, ra, c, signum, alarm_sig, interval);
    }

    return 0;
}

//printing the Results.
void printP(double rtt, int num, int lost, int rec, int sent) {
    printf("%d: RTT: %0.4fms, ",num-1, rtt);
    if (lost > 0) {
        printf("Packet loss: Y, Cumulative Loss Percent: %0.2f.\n", 100 * (1 - ((double)rec)/sent));
    } else {
        printf("Packet loss: N.\n");
    }

}

//Packet handling for IPv4
void v4(int sock, struct sockaddr_in sa, struct sockaddr_in ra, int c, int signum, sigset_t alarm_sig, int interval) {
    int rec = 0, sent = 0, num = 1;
    struct icmphdr head;
    double time1, time2, rtt;
    struct timespec tp;
    int len = sizeof(ra);
    char buf[64];

    while (c == -1 || c > 0) {
        if (interval != 0 && num > 1)
            sigwait(&alarm_sig, &signum);

        int lost = 0;

        bzero(&head, sizeof(head));
        bzero(&buf, sizeof(buf));
        head.type = ICMP_ECHO;
        head.code = 0;
        head.checksum = 0;
        head.un.echo.id = getpid();
        head.un.echo.sequence = htons(num++);
        head.checksum = checksum((uint16_t *)&head, sizeof(head));

        clock_gettime(CLOCK_REALTIME, &tp);
        time1 = ((double)(tp.tv_sec)) + (pow(10, -9) * ((double)(tp.tv_nsec)));
        if (sendto(sock, &head, sizeof(head), 0, (const struct sockaddr *)&sa, sizeof(sa)) <= 0) {
            fprintf(stderr, "Packet send failure: %s.\n", strerror(errno));
            continue;
        } else sent++;

        if (recvfrom(sock, &buf, sizeof(buf), 0, (struct sockaddr *) &ra, (socklen_t *)&len) > 0){
            //fprintf(stderr, "%d; %d; %d, %d\n",r, (int)sizeof(packet),  packet.head.type, packet.head.code);
            struct iphdr *ip_hdr = (struct iphdr *)buf;
            struct icmphdr *icmp_hdr = (struct icmphdr *)((char *)ip_hdr + (4 * ip_hdr->ihl));
            if (icmp_hdr->type == 0 && icmp_hdr->code == 0) {
                rec++;
            }
           // else if (icmp_hdr->type == ICMP_ECHO) {
             //   num--;
             //   continue;
            //}
            else lost++;
            //fprintf(stderr, "%d, %d, %d, %d\n", icmp_hdr->code, icmp_hdr->type, ICMP_ECHO, icmp_hdr->un.echo.sequence);
        } else{
            printf("Receive fail: %s.\n", strerror(errno));
            continue;
        };

        clock_gettime(CLOCK_REALTIME, &tp);
        time2 = ((double)(tp.tv_sec)) + (pow(10, -9) * ((double)(tp.tv_nsec)));
        rtt = 1000 * (time2 - time1);

        printP(rtt, num, lost, rec, sent);

        if (c != -1)
            c--;
    } 
}

//Packet handling for IPv6
void v6(int sock, struct sockaddr_in6 sa, struct sockaddr_in6 ra, int c, int signum, sigset_t alarm_sig, int interval) {
    int rec = 0, sent = 0, num = 1;
    struct icmp6_hdr head;
    double time1, time2, rtt;
    struct timespec tp;
    int len = sizeof(ra);
    char buf[64];

    while (c == -1 || c > 0) {
        if (interval != 0 && num > 1)
            sigwait(&alarm_sig, &signum);

        int lost = 0;

        bzero(&head, sizeof(head));
        bzero(&buf, sizeof(buf));
        head.icmp6_type = ICMP_ECHO;
        head.icmp6_code = 0;
        head.icmp6_dataun.icmp6_un_data16[0] = getpid();
        head.icmp6_dataun.icmp6_un_data16[1] = htons(num++);

        int offset = offsetof(struct icmp6_hdr, icmp6_cksum);
        setsockopt(sock, SOL_RAW, IPV6_CHECKSUM, &offset, sizeof(offset));

        //fprintf(stderr,"%d", s);
        clock_gettime(CLOCK_REALTIME, &tp);
        time1 = ((double)(tp.tv_sec)) + (pow(10, -9) * ((double)(tp.tv_nsec)));
        if (sendto(sock, &head, sizeof(head), 0, (const struct sockaddr *)&sa, sizeof(sa)) <= 0) {
            fprintf(stderr, "Packet send failure: %s.\n", strerror(errno));
            continue;
        } else sent++;

        if (recvfrom(sock, &buf, sizeof(buf), 0, (struct sockaddr *) &ra, (socklen_t *)&len) > 0){
            //fprintf(stderr, "%d; %d; %d, %d\n",r, (int)sizeof(packet),  packet.head.type, packet.head.code);
            struct ipv6_hdr *ip_hdr = (struct ipv6_hdr *)buf;
            struct icmp6_hdr *icmp_hdr = (struct icmp6_hdr *)((char *)ip_hdr + 40);
            if (icmp_hdr->icmp6_type == 0 && icmp_hdr->icmp6_code == 0) {        
                rec++;
            }
            //else if (icmp_hdr->icmp6_type == ICMP_ECHO)
             //   continue;
            else lost++;
            //fprintf(stderr, "%d\n", icmp_hdr->code);
        } else{
            printf("Receive fail: %s.\n", strerror(errno));
            continue;
        };

        clock_gettime(CLOCK_REALTIME, &tp);
        time2 = ((double)(tp.tv_sec)) + (pow(10, -9) * ((double)(tp.tv_nsec)));
        rtt = 1000 * (time2 - time1);

        printP(rtt, num, lost, rec, sent);

        if (c != -1)
            c--;
    } 
}

//Determining the destination.
Addr *setAddr(Addr *sa, char *str){
    int res = inet_pton(AF_INET, str, &(sa->addr.sin_addr));
    if (res != 1){
        res = inet_pton(AF_INET6, str, &(sa->addr6.sin6_addr));
        if (res != 1) {
            struct hostent *he = gethostbyname(str);
            if (he == NULL) {
                fprintf(stderr, "Invalid ip address/hostname.\n");
                exit(-1);
            }
            if (he->h_addrtype == AF_INET) {
                sa->addr.sin_family = AF_INET;
                sa->addr.sin_addr.s_addr = *(long *)he->h_addr;
                sa->which = 0;
            }
            else{
                sa->addr6.sin6_family = AF_INET6;
                memcpy(sa->addr6.sin6_addr.s6_addr, he->h_addr, sizeof(*he->h_addr));
                sa->which = 6;
            }
        } else {
            sa->addr6.sin6_family = AF_INET6;
            sa->which = 6;
            //perror("here");
        }
    } else {
        sa->addr.sin_family = AF_INET;
        sa->which = 0;
        //perror("here");
    }
    return sa;
}

//Checksum for packets.
uint16_t checksum(uint16_t *buf, int l) {
    uint16_t ans;
    uint32_t sum = 0;
    for (; l > 1; l -=2) {
        sum += *buf++;
    }
    if (l == 1)
        sum += *(uint8_t *)buf;
    sum = (sum >> 16) + (sum & 0xffff);
    sum += (sum >> 16);
    ans = ~sum;
    return ans;
}
