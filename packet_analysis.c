#include "cshark.h"

// Packet handler for all packets
void packet_handler(u_char *args, const struct pcap_pkthdr *header, const u_char *packet) {
    (void)args; // Suppress unused parameter warning
    if (stop_sniffing) return;

    packet_count++;
    printf("[DEBUG] packet_handler called for packet #%d\n", packet_count);
    fflush(stdout);
    store_packet(header, packet);
    process_packet(header, packet, 1);
}

// Packet handler for filtered packets
void packet_handler_filtered(u_char *args, const struct pcap_pkthdr *header, const u_char *packet) {
    (void)args; // Suppress unused parameter warning
    if (stop_sniffing) return;

    packet_count++;
    store_packet(header, packet);
    process_packet(header, packet, 1);
}

// Process and display packet information
void process_packet(const struct pcap_pkthdr *header, const u_char *packet, int display) {
    struct ether_header *eth_header;
    
    if (display) {
        printf("%s-----------------------------------------\n%s", COLOR_CYAN, COLOR_RESET);
        printf("%s%sPacket #%d%s | %sTimestamp: %ld.%06ld%s | %sLength: %d bytes%s\n",
               COLOR_BOLD, COLOR_GREEN, packet_count, COLOR_RESET,
               COLOR_YELLOW, header->ts.tv_sec, header->ts.tv_usec, COLOR_RESET,
               COLOR_BLUE, header->len, COLOR_RESET);
    }

    eth_header = (struct ether_header*)packet;
    
    if (display) {
        display_ethernet_header(packet);
    }

    u_int16_t ether_type = ntohs(eth_header->ether_type);
    
    switch (ether_type) {
        case ETHERTYPE_IP:
            if (display) display_ip_header(packet);
            break;
        case ETHERTYPE_IPV6:
            if (display) display_ipv6_header(packet);
            break;
        case ETHERTYPE_ARP:
            if (display) display_arp_header(packet);
            break;
        default:
            if (display) printf("L3: Unknown EtherType (0x%04X)\n", ether_type);
            break;
    }
}

// Display Ethernet header
void display_ethernet_header(const u_char *packet) {
    struct ether_header *eth_header = (struct ether_header*)packet;
    
    printf("%s%sL2 (Ethernet):%s Dst MAC: %s%02X:%02X:%02X:%02X:%02X:%02X%s | Src MAC: %s%02X:%02X:%02X:%02X:%02X:%02X%s |\n",
           COLOR_BOLD, COLOR_MAGENTA, COLOR_RESET,
           COLOR_RED, eth_header->ether_dhost[0], eth_header->ether_dhost[1], eth_header->ether_dhost[2],
           eth_header->ether_dhost[3], eth_header->ether_dhost[4], eth_header->ether_dhost[5], COLOR_RESET,
           COLOR_GREEN, eth_header->ether_shost[0], eth_header->ether_shost[1], eth_header->ether_shost[2],
           eth_header->ether_shost[3], eth_header->ether_shost[4], eth_header->ether_shost[5], COLOR_RESET);

    u_int16_t ether_type = ntohs(eth_header->ether_type);
    switch (ether_type) {
        case ETHERTYPE_IP:
            printf("EtherType: %s%sIPv4%s (%s0x%04X%s)\n", COLOR_BOLD, COLOR_BLUE, COLOR_RESET, COLOR_CYAN, ether_type, COLOR_RESET);
            break;
        case ETHERTYPE_IPV6:
            printf("EtherType: %s%sIPv6%s (%s0x%04X%s)\n", COLOR_BOLD, COLOR_BLUE, COLOR_RESET, COLOR_CYAN, ether_type, COLOR_RESET);
            break;
        case ETHERTYPE_ARP:
            printf("EtherType: %s%sARP%s (%s0x%04X%s)\n", COLOR_BOLD, COLOR_YELLOW, COLOR_RESET, COLOR_CYAN, ether_type, COLOR_RESET);
            break;
        default:
            printf("EtherType: %s%sUnknown%s (%s0x%04X%s)\n", COLOR_BOLD, COLOR_RED, COLOR_RESET, COLOR_CYAN, ether_type, COLOR_RESET);
            break;
    }
}

// Display IPv4 header
void display_ip_header(const u_char *packet) {
    struct iphdr *ip_header = (struct iphdr*)(packet + sizeof(struct ether_header));
    struct sockaddr_in source, dest;
    char src_ip_str[INET_ADDRSTRLEN], dst_ip_str[INET_ADDRSTRLEN];

    memset(&source, 0, sizeof(source));
    source.sin_addr.s_addr = ip_header->saddr;
    memset(&dest, 0, sizeof(dest));
    dest.sin_addr.s_addr = ip_header->daddr;

    // Convert IP addresses to strings safely
    strcpy(src_ip_str, inet_ntoa(source.sin_addr));
    strcpy(dst_ip_str, inet_ntoa(dest.sin_addr));

    printf("%s%sL3 (IPv4):%s Src IP: %s%s%s | Dst IP: %s%s%s | ", 
           COLOR_BOLD, COLOR_BLUE, COLOR_RESET,
           COLOR_GREEN, src_ip_str, COLOR_RESET,
           COLOR_RED, dst_ip_str, COLOR_RESET);

    switch (ip_header->protocol) {
        case IPPROTO_TCP:
            printf("Protocol: %s%sTCP%s (%s%d%s) |\n", COLOR_BOLD, COLOR_CYAN, COLOR_RESET, COLOR_YELLOW, ip_header->protocol, COLOR_RESET);
            break;
        case IPPROTO_UDP:
            printf("Protocol: %s%sUDP%s (%s%d%s) |\n", COLOR_BOLD, COLOR_MAGENTA, COLOR_RESET, COLOR_YELLOW, ip_header->protocol, COLOR_RESET);
            break;
        case IPPROTO_ICMP:
            printf("Protocol: %s%sICMP%s (%s%d%s) |\n", COLOR_BOLD, COLOR_GREEN, COLOR_RESET, COLOR_YELLOW, ip_header->protocol, COLOR_RESET);
            break;
        default:
            printf("Protocol: %s%sUnknown%s (%s%d%s) |\n", COLOR_BOLD, COLOR_RED, COLOR_RESET, COLOR_YELLOW, ip_header->protocol, COLOR_RESET);
            break;
    }

    printf("TTL: %s%d%s\n", COLOR_CYAN, ip_header->ttl, COLOR_RESET);
    printf("ID: %s0x%04X%s | Total Length: %s%d%s | Header Length: %s%d%s bytes\n",
           COLOR_YELLOW, ntohs(ip_header->id), COLOR_RESET,
           COLOR_GREEN, ntohs(ip_header->tot_len), COLOR_RESET,
           COLOR_BLUE, ip_header->ihl * 4, COLOR_RESET);

    // Process transport layer
    int ip_header_len = ip_header->ihl * 4;
    switch (ip_header->protocol) {
        case IPPROTO_TCP:
            display_tcp_header(packet, ip_header_len);
            break;
        case IPPROTO_UDP:
            display_udp_header(packet, ip_header_len);
            break;
    }
}

// Display IPv6 header
void display_ipv6_header(const u_char *packet) {
    struct ip6_hdr *ip6_header = (struct ip6_hdr*)(packet + sizeof(struct ether_header));
    char src_ip[INET6_ADDRSTRLEN], dst_ip[INET6_ADDRSTRLEN];

    inet_ntop(AF_INET6, &ip6_header->ip6_src, src_ip, INET6_ADDRSTRLEN);
    inet_ntop(AF_INET6, &ip6_header->ip6_dst, dst_ip, INET6_ADDRSTRLEN);

    printf("L3 (IPv6): Src IP: %s | Dst IP: %s\n", src_ip, dst_ip);

    switch (ip6_header->ip6_nxt) {
        case IPPROTO_TCP:
            printf("Next Header: TCP (%d) | ", ip6_header->ip6_nxt);
            break;
        case IPPROTO_UDP:
            printf("Next Header: UDP (%d) | ", ip6_header->ip6_nxt);
            break;
        default:
            printf("Next Header: Unknown (%d) | ", ip6_header->ip6_nxt);
            break;
    }

    printf("Hop Limit: %d | Traffic Class: %d | Flow Label: 0x%05X | Payload Length: %d\n",
           ip6_header->ip6_hlim, 
           (ntohl(ip6_header->ip6_flow) >> 20) & 0xFF,
           ntohl(ip6_header->ip6_flow) & 0xFFFFF,
           ntohs(ip6_header->ip6_plen));

    // Process transport layer
    int ip6_header_len = 40; // IPv6 header is always 40 bytes
    switch (ip6_header->ip6_nxt) {
        case IPPROTO_TCP:
            display_tcp_header(packet, ip6_header_len);
            break;
        case IPPROTO_UDP:
            display_udp_header(packet, ip6_header_len);
            break;
    }
}

// Display ARP header
void display_arp_header(const u_char *packet) {
    struct arphdr *arp_header = (struct arphdr*)(packet + sizeof(struct ether_header));
    
    printf("\nL3 (ARP): Operation: ");
    switch (ntohs(arp_header->ar_op)) {
        case ARPOP_REQUEST:
            printf("Request (1) | ");
            break;
        case ARPOP_REPLY:
            printf("Reply (2) | ");
            break;
        default:
            printf("Unknown (%d) | ", ntohs(arp_header->ar_op));
            break;
    }

    // Extract sender and target addresses
    u_char *arp_data = (u_char*)(arp_header + 1);
    u_char *sender_mac = arp_data;
    u_char *sender_ip = arp_data + 6;
    u_char *target_mac = arp_data + 10;
    u_char *target_ip = arp_data + 16;

    printf("Sender IP: %d.%d.%d.%d | Target IP: %d.%d.%d.%d\n",
           sender_ip[0], sender_ip[1], sender_ip[2], sender_ip[3],
           target_ip[0], target_ip[1], target_ip[2], target_ip[3]);

    printf("Sender MAC: %02X:%02X:%02X:%02X:%02X:%02X | Target MAC: %02X:%02X:%02X:%02X:%02X:%02X\n",
           sender_mac[0], sender_mac[1], sender_mac[2], sender_mac[3], sender_mac[4], sender_mac[5],
           target_mac[0], target_mac[1], target_mac[2], target_mac[3], target_mac[4], target_mac[5]);

    printf("HW Type: %d | Proto Type: 0x%04X | HW Len: %d | Proto Len: %d\n",
           ntohs(arp_header->ar_hrd), ntohs(arp_header->ar_pro),
           arp_header->ar_hln, arp_header->ar_pln);
}

// Display TCP header
void display_tcp_header(const u_char *packet, int ip_header_len) {
    struct tcp_header *tcp_header = (struct tcp_header*)(packet + sizeof(struct ether_header) + ip_header_len);
    
    int src_port = ntohs(tcp_header->th_sport);
    int dst_port = ntohs(tcp_header->th_dport);

    printf("%s%sL4 (TCP):%s Src Port: %s%d%s", COLOR_BOLD, COLOR_CYAN, COLOR_RESET, COLOR_GREEN, src_port, COLOR_RESET);
    const char *src_service = get_port_name(src_port);
    if (src_service) printf(" (%s%s%s)", COLOR_YELLOW, src_service, COLOR_RESET);

    printf(" | Dst Port: %s%d%s", COLOR_RED, dst_port, COLOR_RESET);
    const char *dst_service = get_port_name(dst_port);
    if (dst_service) printf(" (%s%s%s)", COLOR_YELLOW, dst_service, COLOR_RESET);

    printf(" | Seq: %s%u%s | Ack: %s%u%s | Flags: [%s",
           COLOR_BLUE, ntohl(tcp_header->th_seq), COLOR_RESET,
           COLOR_MAGENTA, ntohl(tcp_header->th_ack), COLOR_RESET, COLOR_BOLD);

    int first_flag = 1;
    if (tcp_header->th_flags & TH_SYN) {
        printf("SYN"); first_flag = 0;
    }
    if (tcp_header->th_flags & TH_ACK) {
        if (!first_flag) printf(",");
        printf("ACK"); first_flag = 0;
    }
    if (tcp_header->th_flags & TH_FIN) {
        if (!first_flag) printf(",");
        printf("FIN"); first_flag = 0;
    }
    if (tcp_header->th_flags & TH_RST) {
        if (!first_flag) printf(",");
        printf("RST"); first_flag = 0;
    }
    if (tcp_header->th_flags & TH_PUSH) {
        if (!first_flag) printf(",");
        printf("PSH"); first_flag = 0;
    }
    if (tcp_header->th_flags & TH_URG) {
        if (!first_flag) printf(",");
        printf("URG"); first_flag = 0;
    }

    printf("%s]\n", COLOR_RESET);
    printf("Window: %s%d%s | Checksum: %s0x%04X%s | Header Length: %s%d%s bytes\n",
           COLOR_GREEN, ntohs(tcp_header->th_win), COLOR_RESET,
           COLOR_YELLOW, ntohs(tcp_header->th_sum), COLOR_RESET,
           COLOR_BLUE, TH_OFF(tcp_header) * 4, COLOR_RESET);

    // Display payload
    int total_headers_len = sizeof(struct ether_header) + ip_header_len + (TH_OFF(tcp_header) * 4);
    display_payload(packet, stored_packets[stored_count - 1].length, total_headers_len, src_port, dst_port);
}

// Display UDP header
void display_udp_header(const u_char *packet, int ip_header_len) {
    struct udphdr *udp_header = (struct udphdr*)(packet + sizeof(struct ether_header) + ip_header_len);
    
    int src_port = ntohs(udp_header->uh_sport);
    int dst_port = ntohs(udp_header->uh_dport);

    printf("%s%sL4 (UDP):%s Src Port: %s%d%s", COLOR_BOLD, COLOR_MAGENTA, COLOR_RESET, COLOR_GREEN, src_port, COLOR_RESET);
    const char *src_service = get_port_name(src_port);
    if (src_service) printf(" (%s%s%s)", COLOR_YELLOW, src_service, COLOR_RESET);

    printf(" | Dst Port: %s%d%s", COLOR_RED, dst_port, COLOR_RESET);
    const char *dst_service = get_port_name(dst_port);
    if (dst_service) printf(" (%s%s%s)", COLOR_YELLOW, dst_service, COLOR_RESET);

    printf(" | Length: %s%d%s | Checksum: %s0x%04X%s\n",
           COLOR_BLUE, ntohs(udp_header->uh_ulen), COLOR_RESET,
           COLOR_CYAN, ntohs(udp_header->uh_sum), COLOR_RESET);

    // Display payload
    int total_headers_len = sizeof(struct ether_header) + ip_header_len + sizeof(struct udphdr);
    display_payload(packet, stored_packets[stored_count - 1].length, total_headers_len, src_port, dst_port);
}