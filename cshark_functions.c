#include "cshark.h"

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
