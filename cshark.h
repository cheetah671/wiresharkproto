#ifndef CSHARK_H
#define CSHARK_H

#define _DEFAULT_SOURCE
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>
#include <signal.h>
#include <time.h>
#include <errno.h>
#include <sys/types.h>
#include <sys/socket.h>
#include <ctype.h>
#include <endian.h>
#include <pcap.h>
#include <net/ethernet.h>
#include <netinet/ip.h>
#include <netinet/ip6.h>
#include <netinet/tcp.h>
#include <netinet/udp.h>
#include <netinet/ip_icmp.h>
#include <net/if_arp.h>
#include <arpa/inet.h>

// ANSI Color codes for terminal output
#define COLOR_RESET     "\033[0m"
#define COLOR_RED       "\033[31m"
#define COLOR_GREEN     "\033[32m"
#define COLOR_YELLOW    "\033[33m"
#define COLOR_BLUE      "\033[34m"
#define COLOR_MAGENTA   "\033[35m"
#define COLOR_CYAN      "\033[36m"
#define COLOR_WHITE     "\033[37m"
#define COLOR_BOLD      "\033[1m"
#define COLOR_UNDERLINE "\033[4m"

// Define missing types for compatibility
#ifndef u_char
typedef unsigned char u_char;
#endif
#ifndef u_short
typedef unsigned short u_short;
#endif
#ifndef u_int
typedef unsigned int u_int;
#endif

// Define TCP header structure 
struct tcp_header {
    u_short th_sport;    /* source port */
    u_short th_dport;    /* destination port */
    u_int th_seq;        /* sequence number */
    u_int th_ack;        /* acknowledgement number */
    u_char th_off_x2;    /* data offset and reserved bits */
    u_char th_flags;
    u_short th_win;      /* window */
    u_short th_sum;      /* checksum */
    u_short th_urp;      /* urgent pointer */
};

// Define TCP flags
#define TH_FIN  0x01
#define TH_SYN  0x02
#define TH_RST  0x04
#define TH_PUSH 0x08
#define TH_ACK  0x10
#define TH_URG  0x20

// Macro to get data offset from th_off_x2
#define TH_OFF(th) (((th)->th_off_x2 & 0xf0) >> 4)

#define MAX_PACKETS 10000
#define SNAP_LEN 65535

// Packet storage structure
typedef struct {
    int id;
    struct timeval timestamp;
    int length;
    u_char *data;
} stored_packet_t;

// Global variables (declared as extern in header)
extern pcap_t *handle;
extern int packet_count;
extern volatile int stop_sniffing;
extern stored_packet_t stored_packets[MAX_PACKETS];
extern int stored_count;

// Function declarations
void signal_handler(int sig);
void display_interfaces();
int select_interface(char *device);
void main_menu(const char *device);
void start_sniffing_all(const char *device);
void start_sniffing_filtered(const char *device);
void inspect_last_session();
void packet_handler(u_char *args, const struct pcap_pkthdr *header, const u_char *packet);
void packet_handler_filtered(u_char *args, const struct pcap_pkthdr *header, const u_char *packet);
void process_packet(const struct pcap_pkthdr *header, const u_char *packet, int display);
void display_ethernet_header(const u_char *packet);
void display_ip_header(const u_char *packet);
void display_ipv6_header(const u_char *packet);
void display_arp_header(const u_char *packet);
void display_tcp_header(const u_char *packet, int ip_header_len);
void display_udp_header(const u_char *packet, int ip_header_len);
void display_payload(const u_char *packet, int total_len, int headers_len, int src_port, int dst_port);
void print_hex_dump(const u_char *data, int length);
void print_hex_ascii_line(const u_char *payload, int len, int offset);
const char* get_port_name(int port);
void free_stored_packets();
void store_packet(const struct pcap_pkthdr *header, const u_char *packet);
void display_packet_summary(int index);

#endif // CSHARK_H