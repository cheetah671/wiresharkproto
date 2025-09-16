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