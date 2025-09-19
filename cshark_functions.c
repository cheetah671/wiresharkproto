#include "cshark.h"

// Signal handler for Ctrl+C
void signal_handler(int sig) {
    if (sig == SIGINT) {
        stop_sniffing = 1;
        if (handle) {
            pcap_breakloop(handle);
        }
    }
}

// Display available network interfaces
void display_interfaces() {
    pcap_if_t *interfaces, *temp;
    char errbuf[PCAP_ERRBUF_SIZE];
    int count = 0;

    printf("[C-Shark] Searching for available interfaces... Found!\n\n");

    if (pcap_findalldevs(&interfaces, errbuf) == -1) {
        fprintf(stderr, "Error finding devices: %s\n", errbuf);
        exit(1);
    }

    for (temp = interfaces; temp; temp = temp->next) {
        count++;
        printf("%d. %s", count, temp->name);
        if (temp->description) {
            printf(" (%s)", temp->description);
        }
        printf("\n");
    }

    pcap_freealldevs(interfaces);
}

// Select network interface
int select_interface(char *device) {
    pcap_if_t *interfaces, *temp;
    char errbuf[PCAP_ERRBUF_SIZE];
    int choice, count = 0;

    // First display all available interfaces
    display_interfaces();

    if (pcap_findalldevs(&interfaces, errbuf) == -1) {
        fprintf(stderr, "Error finding devices: %s\n", errbuf);
        return -1;
    }

    printf("\nSelect an interface to sniff (1-");
    for (temp = interfaces; temp; temp = temp->next) count++;
    printf("%d): ", count);

    if (scanf("%d", &choice) != 1) {
        // Handle EOF (Ctrl+D) or invalid input
        printf("\nExiting C-Shark. Goodbye!\n");
        pcap_freealldevs(interfaces);
        free_stored_packets();
        exit(0);
    }
    getchar(); // consume newline

    if (choice < 1 || choice > count) {
        printf("Invalid selection!\n");
        pcap_freealldevs(interfaces);
        return -1;
    }

    temp = interfaces;
    for (int i = 1; i < choice; i++) {
        temp = temp->next;
    }

    strcpy(device, temp->name);
    pcap_freealldevs(interfaces);
    return 0;
}

// Main menu
void main_menu(const char *device) {
    int choice;

    while (1) {
        printf("\n%s%s[C-Shark]%s Interface '%s%s%s' selected. What's next?\n\n", 
               COLOR_BOLD, COLOR_CYAN, COLOR_RESET, COLOR_GREEN, device, COLOR_RESET);
        printf("%s1.%s Start Sniffing (%sAll Packets%s)\n", COLOR_BOLD, COLOR_RESET, COLOR_GREEN, COLOR_RESET);
        printf("%s2.%s Start Sniffing (%sWith Filters%s)\n", COLOR_BOLD, COLOR_RESET, COLOR_YELLOW, COLOR_RESET);
        printf("%s3.%s Inspect Last Session\n", COLOR_BOLD, COLOR_RESET);
        printf("%s4.%s Exit C-Shark\n\n", COLOR_BOLD, COLOR_RESET);
        printf("%sEnter your choice:%s ", COLOR_BOLD, COLOR_RESET);

        if (scanf("%d", &choice) != 1) {
            // Handle EOF (Ctrl+D) or invalid input
            printf("\nExiting C-Shark. Goodbye!\n");
            free_stored_packets();
            exit(0);
        }
        getchar(); // consume newline

        switch (choice) {
            case 1:
                start_sniffing_all(device);
                break;
            case 2:
                start_sniffing_filtered(device);
                break;
            case 3:
                inspect_last_session();
                break;
            case 4:
                printf("Exiting C-Shark. Goodbye!\n");
                free_stored_packets();
                exit(0);
            default:
                printf("Invalid choice! Please try again.\n");
        }
    }
}

// Start sniffing all packets
void start_sniffing_all(const char *device) {
    char errbuf[PCAP_ERRBUF_SIZE];

    // Free previous session data
    free_stored_packets();

    handle = pcap_open_live(device, SNAP_LEN, 1, 1000, errbuf);
    if (handle == NULL) {
        fprintf(stderr, "Couldn't open device %s: %s\n", device, errbuf);
        return;
    }

    printf("\n%s%s[C-Shark]%s Starting packet capture on %s%s%s...\n", 
           COLOR_BOLD, COLOR_GREEN, COLOR_RESET, COLOR_CYAN, device, COLOR_RESET);
    printf("%sPress Ctrl+C to stop sniffing and return to menu.%s\n\n", COLOR_YELLOW, COLOR_RESET);

    packet_count = 0;
    stop_sniffing = 0;
    signal(SIGINT, signal_handler);

    pcap_loop(handle, -1, packet_handler, NULL);

    pcap_close(handle);
    handle = NULL;
    signal(SIGINT, SIG_DFL);
    printf("\n[C-Shark] Capture stopped. Captured %d packets.\n", packet_count);
    printf("[C-Shark] Stored %d packets for inspection.\n", stored_count);
}

// Start sniffing with filters
void start_sniffing_filtered(const char *device) {
    char errbuf[PCAP_ERRBUF_SIZE];
    char filter_exp[256];
    struct bpf_program fp;
    int choice;

    printf("\nSelect filter type:\n");
    printf("1. HTTP (port 80)\n");
    printf("2. HTTPS (port 443)\n");
    printf("3. DNS (port 53)\n");
    printf("4. ARP\n");
    printf("5. TCP\n");
    printf("6. UDP\n");
    printf("Enter choice: ");

    if (scanf("%d", &choice) != 1) {
        // Handle EOF (Ctrl+D) or invalid input
        printf("\nExiting C-Shark. Goodbye!\n");
        free_stored_packets();
        exit(0);
    }
    getchar();

    switch (choice) {
        case 1:
            strcpy(filter_exp, "port 80");
            break;
        case 2:
            strcpy(filter_exp, "port 443");
            break;
        case 3:
            strcpy(filter_exp, "port 53");
            break;
        case 4:
            strcpy(filter_exp, "arp");
            break;
        case 5:
            strcpy(filter_exp, "tcp");
            break;
        case 6:
            strcpy(filter_exp, "udp");
            break;
        default:
            printf("Invalid choice!\n");
            return;
    }

    // Free previous session data
    free_stored_packets();

    handle = pcap_open_live(device, SNAP_LEN, 1, 1000, errbuf);
    if (handle == NULL) {
        fprintf(stderr, "Couldn't open device %s: %s\n", device, errbuf);
        return;
    }

    if (pcap_compile(handle, &fp, filter_exp, 0, PCAP_NETMASK_UNKNOWN) == -1) {
        fprintf(stderr, "Couldn't parse filter %s: %s\n", filter_exp, pcap_geterr(handle));
        pcap_close(handle);
        return;
    }

    if (pcap_setfilter(handle, &fp) == -1) {
        fprintf(stderr, "Couldn't install filter %s: %s\n", filter_exp, pcap_geterr(handle));
        pcap_close(handle);
        return;
    }

    printf("\n[C-Shark] Starting filtered capture (%s) on %s...\n", filter_exp, device);
    printf("Press Ctrl+C to stop sniffing and return to menu.\n\n");

    packet_count = 0;
    stop_sniffing = 0;
    signal(SIGINT, signal_handler);

    pcap_loop(handle, -1, packet_handler_filtered, NULL);

    pcap_freecode(&fp);
    pcap_close(handle);
    handle = NULL;
    signal(SIGINT, SIG_DFL);
    printf("\n[C-Shark] Filtered capture stopped. Captured %d packets.\n", packet_count);
    printf("[C-Shark] Stored %d packets for inspection.\n", stored_count);
}
