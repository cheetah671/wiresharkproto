#include "cshark.h"

// Display payload
void display_payload(const u_char *packet, int total_len, int headers_len, int src_port, int dst_port) {
    int payload_len = total_len - headers_len;
    
    if (payload_len <= 0) return;

    printf("%s%sL7 (Payload):%s Identified as ", COLOR_BOLD, COLOR_YELLOW, COLOR_RESET);
    
    // Identify protocol based on ports
    if (src_port == 80 || dst_port == 80) {
        printf("%s%sHTTP%s", COLOR_BOLD, COLOR_GREEN, COLOR_RESET);
    } else if (src_port == 443 || dst_port == 443) {
        printf("%s%sHTTPS/TLS%s", COLOR_BOLD, COLOR_RED, COLOR_RESET);
    } else if (src_port == 53 || dst_port == 53) {
        printf("%s%sDNS%s", COLOR_BOLD, COLOR_BLUE, COLOR_RESET);
    } else {
        printf("%s%sUnknown%s", COLOR_BOLD, COLOR_MAGENTA, COLOR_RESET);
    }
    
    printf(" on port %s%d%s - %s%d%s bytes\n", 
           COLOR_CYAN, (src_port == 80 || src_port == 443 || src_port == 53) ? src_port : dst_port, COLOR_RESET,
           COLOR_YELLOW, payload_len, COLOR_RESET);

    const u_char *payload = packet + headers_len;
    int display_len = (payload_len > 64) ? 64 : payload_len;
    
    if (payload_len > 64) {
        printf("%sData (first 64 bytes):%s\n", COLOR_UNDERLINE, COLOR_RESET);
    } else {
        printf("%sData (first %d bytes):%s\n", COLOR_UNDERLINE, payload_len, COLOR_RESET);
    }
    
    print_hex_dump(payload, display_len);
}

// Print hex dump
void print_hex_dump(const u_char *data, int length) {
    const u_char *ch = data;
    int i;

    for (i = 0; i < length; i += 16) {
        print_hex_ascii_line(ch, length - i, i);
        ch += 16;
    }
}

// Print a single line of hex and ASCII
void print_hex_ascii_line(const u_char *payload, int len, int offset) {
    (void)offset; // Suppress unused parameter warning
    int i;
    int gap;
    const u_char *ch;

    // Print hex
    ch = payload;
    for (i = 0; i < len && i < 16; i++) {
        printf("%02X ", *ch);
        ch++;
    }

    // Print padding if needed
    if (len < 16) {
        gap = 16 - len;
        for (i = 0; i < gap; i++) {
            printf("   ");
        }
    }

    // Print ASCII
    ch = payload;
    for (i = 0; i < len && i < 16; i++) {
        if (isprint(*ch))
            printf("%c", *ch);
        else
            printf(".");
        ch++;
    }

    printf("\n");
}

// Get service name for common ports
const char* get_port_name(int port) {
    switch (port) {
        case 80: return "HTTP";
        case 443: return "HTTPS";
        case 53: return "DNS";
        case 22: return "SSH";
        case 23: return "Telnet";
        case 25: return "SMTP";
        case 110: return "POP3";
        case 143: return "IMAP";
        case 993: return "IMAPS";
        case 995: return "POP3S";
        default: return NULL;
    }
}

// Store packet in memory
void store_packet(const struct pcap_pkthdr *header, const u_char *packet) {
    if (stored_count >= MAX_PACKETS) {
        // Remove oldest packet
        free(stored_packets[0].data);
        memmove(&stored_packets[0], &stored_packets[1], (MAX_PACKETS - 1) * sizeof(stored_packet_t));
        stored_count--;
    }

    stored_packets[stored_count].id = packet_count;
    stored_packets[stored_count].timestamp = header->ts;
    stored_packets[stored_count].length = header->len;
    stored_packets[stored_count].data = malloc(header->len);
    if (stored_packets[stored_count].data == NULL) {
        fprintf(stderr, "Error: Failed to allocate memory for packet storage\n");
        return;
    }
    memcpy(stored_packets[stored_count].data, packet, header->len);
    stored_count++;
    
    // Debug: print every 10th packet
    if (stored_count % 10 == 0) {
        printf("[DEBUG] Stored packet #%d, total stored: %d\n", packet_count, stored_count);
        fflush(stdout);
    }
}

// Free stored packets
void free_stored_packets() {
    printf("[DEBUG] free_stored_packets called - clearing %d packets\n", stored_count);
    fflush(stdout);
    for (int i = 0; i < stored_count; i++) {
        free(stored_packets[i].data);
    }
    stored_count = 0;
}

// Display packet summary for inspection
void display_packet_summary(int index) {
    struct ether_header *eth_header = (struct ether_header*)stored_packets[index].data;
    u_int16_t ether_type = ntohs(eth_header->ether_type);
    
    printf("%d. Packet #%d | %ld.%06ld | %d bytes | ",
           index + 1, stored_packets[index].id,
           stored_packets[index].timestamp.tv_sec,
           stored_packets[index].timestamp.tv_usec,
           stored_packets[index].length);

    switch (ether_type) {
        case ETHERTYPE_IP: {
            struct iphdr *ip_header = (struct iphdr*)(stored_packets[index].data + sizeof(struct ether_header));
            struct sockaddr_in src, dst;
            src.sin_addr.s_addr = ip_header->saddr;
            dst.sin_addr.s_addr = ip_header->daddr;
            printf("IPv4: %s -> %s", inet_ntoa(src.sin_addr), inet_ntoa(dst.sin_addr));
            break;
        }
        case ETHERTYPE_IPV6: {
            char src_ip[INET6_ADDRSTRLEN], dst_ip[INET6_ADDRSTRLEN];
            struct ip6_hdr *ip6_header = (struct ip6_hdr*)(stored_packets[index].data + sizeof(struct ether_header));
            inet_ntop(AF_INET6, &ip6_header->ip6_src, src_ip, INET6_ADDRSTRLEN);
            inet_ntop(AF_INET6, &ip6_header->ip6_dst, dst_ip, INET6_ADDRSTRLEN);
            printf("IPv6: %s -> %s", src_ip, dst_ip);
            break;
        }
        case ETHERTYPE_ARP:
            printf("ARP");
            break;
        default:
            printf("Unknown");
            break;
    }
    printf("\n");
}

// Display detailed packet information
void display_detailed_packet(int packet_id) {
    int found = -1;
    for (int i = 0; i < stored_count; i++) {
        if (stored_packets[i].id == packet_id) {
            found = i;
            break;
        }
    }

    if (found == -1) {
        printf("Packet #%d not found in stored packets!\n", packet_id);
        return;
    }

    printf("\n========== DETAILED PACKET ANALYSIS ==========\n");
    printf("Packet ID: %d\n", stored_packets[found].id);
    printf("Timestamp: %ld.%06ld\n", stored_packets[found].timestamp.tv_sec, stored_packets[found].timestamp.tv_usec);
    printf("Total Length: %d bytes\n", stored_packets[found].length);
    
    printf("\n--- FULL HEX DUMP ---\n");
    print_hex_dump(stored_packets[found].data, stored_packets[found].length);
    
    printf("\n--- LAYER ANALYSIS ---\n");
    
    // Create a fake header for process_packet
    struct pcap_pkthdr fake_header;
    fake_header.ts = stored_packets[found].timestamp;
    fake_header.len = stored_packets[found].length;
    fake_header.caplen = stored_packets[found].length;
    
    // Temporarily set packet_count for display
    int old_count = packet_count;
    packet_count = stored_packets[found].id;
    
    process_packet(&fake_header, stored_packets[found].data, 1);
    
    packet_count = old_count;
    printf("=============================================\n");
}

// Inspect last session
void inspect_last_session() {
    printf("[DEBUG] inspect_last_session: stored_count = %d\n", stored_count);
    fflush(stdout);
    if (stored_count == 0) {
        printf("No packets stored from previous sessions!\n");
        return;
    }

    printf("\n========== LAST SESSION PACKETS ==========\n");
    printf("Total packets stored: %d\n\n", stored_count);

    for (int i = 0; i < stored_count; i++) {
        display_packet_summary(i);
    }

    printf("\nEnter Packet ID to inspect in detail (0 to return): ");
    int packet_id;
    if (scanf("%d", &packet_id) != 1) {
        // Handle EOF (Ctrl+D) or invalid input
        printf("\nExiting C-Shark. Goodbye!\n");
        free_stored_packets();
        exit(0);
    }
    getchar();

    if (packet_id > 0) {
        display_detailed_packet(packet_id);
    }
}