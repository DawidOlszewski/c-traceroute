#include <arpa/inet.h>
#include <errno.h>
#include <netinet/ip.h>
#include <netinet/in.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/select.h>

#include <time.h>
#include <unistd.h>
#include <strings.h>

#include <arpa/inet.h>
#include <errno.h>
#include <netinet/ip.h>
#include <netinet/ip_icmp.h>
#include <sys/time.h>
#include <assert.h>

#define ttl_max 30
#define SECS2WAIT 1

void check(int result, char *message)
{
    if (result < 0)
    {
        fprintf(stderr, "%s : %s\n", message, strerror(errno));
        exit(EXIT_FAILURE);
    }
}

u_int16_t compute_icmp_checksum(const void *buff, int length)
{
    const u_int16_t *ptr = buff;
    u_int32_t sum = 0;
    assert(length % 2 == 0);
    for (; length > 0; length -= 2)
        sum += *ptr++;
    sum = (sum >> 16U) + (sum & 0xffffU);
    return (u_int16_t)(~(sum + (sum >> 16U)));
}

struct icmp create_icpm(int ttl, int pid)
{
    struct icmp header;
    header.icmp_type = ICMP_ECHO;
    header.icmp_code = 0;
    header.icmp_hun.ih_idseq.icd_id = pid;
    header.icmp_hun.ih_idseq.icd_seq = ttl;
    header.icmp_cksum = 0;
    header.icmp_cksum = compute_icmp_checksum(
        (u_int16_t *)&header, sizeof(header));
    return header;
}

void send_icmp(int sockfd, struct sockaddr_in recipient, int ttl, int pid)
{
    struct icmp header = create_icpm(ttl, pid);
    setsockopt(sockfd, IPPROTO_IP, IP_TTL, &ttl, sizeof(int));
    ssize_t bytes_sent = sendto(
        sockfd,
        &header,
        sizeof(header),
        0,
        (struct sockaddr *)&recipient,
        sizeof(recipient));
    check(bytes_sent, "sendto");
}

struct packet_info
{
    char sender_ip_str[20];
    struct timeval end_time;
};

void receive_ours(u_int8_t buffer[IP_MAXPACKET], struct packet_info pis[3], int *recived_packets, int pid, int ttl, int *finish, char sender[20])
{

    struct timeval end_time;

    struct ip *ip_header = (struct ip *)buffer;
    u_int8_t *icmp_packet = buffer + 4 * ip_header->ip_hl;
    struct icmp *icmp_header = (struct icmp *)icmp_packet;

    if (
        icmp_header->icmp_type != ICMP_ECHOREPLY &&
        icmp_header->icmp_type != ICMP_TIME_EXCEEDED)
        return;

    struct icmp *org_icmp_header = icmp_header;
    if (icmp_header->icmp_type == ICMP_TIME_EXCEEDED)
    {
        struct ip *org_ip_header = (void *)icmp_header + 8;
        org_icmp_header = (void *)org_ip_header + 4 * org_ip_header->ip_hl;
    }

    if (
        org_icmp_header->icmp_hun.ih_idseq.icd_id != pid &&
        org_icmp_header->icmp_hun.ih_idseq.icd_seq != ttl)
        return;

    gettimeofday(&end_time, NULL);
    pis[*recived_packets].end_time = end_time;
    strcpy(pis[*recived_packets].sender_ip_str, sender);
    (*recived_packets)++;

    if (icmp_header->icmp_type == ICMP_ECHOREPLY)
    {
        *finish = 1;
    }
}

struct sockaddr_in get_recipient(char *ip_str)
{
    struct sockaddr_in recipient;
    bzero(&recipient, sizeof(recipient));
    recipient.sin_family = AF_INET;
    if (inet_pton(AF_INET, ip_str, &recipient.sin_addr) <= 0)
    {
        printf("inet_pton :  wrong ip input provided");
        exit(EXIT_FAILURE);
    }
    return recipient;
}

void check_args(int argc)
{
    if (argc != 2)
    {
        printf("pls provide input in format: `sudo [command_name] ip`");
        exit(EXIT_FAILURE);
    }
}

int msdiff(struct timeval end_time, struct timeval start_time)
{
    int sec = (end_time.tv_sec - start_time.tv_sec) * 1000;
    int usec = (end_time.tv_usec - start_time.tv_usec) / 1000;
    return sec + usec;
}

void print_results(struct packet_info pis[3], int packets, struct timeval start_time, int ttl)
{

    printf("%d. ", ttl);

    if (packets >= 1)
    {
        printf("%s ", pis[0].sender_ip_str);
    }
    if (packets >= 2 && strcmp(pis[0].sender_ip_str, pis[1].sender_ip_str))
    {
        printf("%s ", pis[1].sender_ip_str);
    }
    if (packets == 3 && strcmp(pis[2].sender_ip_str, pis[1].sender_ip_str) && strcmp(pis[2].sender_ip_str, pis[0].sender_ip_str))
    {
        printf("%s ", pis[2].sender_ip_str);
    }
    if (packets == 0)
    {
        printf("*");
    }
    else if (packets != 3)
    {
        printf("???");
    }
    else
    {
        int mediumtime = (msdiff(pis[0].end_time, start_time) + msdiff(pis[1].end_time, start_time) + msdiff(pis[2].end_time, start_time)) / 3;
        printf("%d ms", mediumtime);
    }
    printf("\n");
}

int main(int argc, char *argv[])
{
    check_args(argc);

    int res = 0, finish = 0;
    struct sockaddr_in sender;
    char sender_ip_str[20];
    socklen_t sender_len = sizeof(sender);
    u_int8_t buffer[IP_MAXPACKET];
    struct packet_info received_packets_info[3]; // new type TODO: ad

    int pid = getpid();

    int sock_fd = socket(AF_INET, SOCK_RAW, IPPROTO_ICMP);
    check(sock_fd, "socket creation");

    struct sockaddr_in recipient = get_recipient(argv[1]);

    for (int ttl = 1; ttl <= 30; ttl++)
    {
        struct timeval start_time;
        gettimeofday(&start_time, NULL);

        send_icmp(sock_fd, recipient, ttl, pid);
        send_icmp(sock_fd, recipient, ttl, pid);
        send_icmp(sock_fd, recipient, ttl, pid);

        fd_set descriptors;

        struct timeval tv;
        tv.tv_sec = SECS2WAIT;
        tv.tv_usec = 0;
        int recived_packets = 0;
        while (1)
        {
            FD_ZERO(&descriptors);
            FD_SET(sock_fd, &descriptors);
            res = select(sock_fd + 1, &descriptors, NULL, NULL, &tv);
            check(res, "select");
            if (res == 0) // timeout
            {
                break;
            }
            ssize_t packet_len = recvfrom(sock_fd, buffer, IP_MAXPACKET, 0, (struct sockaddr *)&sender, &sender_len);
            inet_ntop(AF_INET, &(sender.sin_addr), sender_ip_str, sizeof(sender_ip_str));
            check(packet_len, "recvfrom");
            receive_ours(buffer, received_packets_info, &recived_packets, pid, ttl, &finish, sender_ip_str);
        }

        print_results(received_packets_info, recived_packets, start_time, ttl);
        if (finish)
        {
            break;
        }
    }
}