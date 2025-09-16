#include "cshark.h"

// Global variable definitions
pcap_t *handle = NULL;
int packet_count = 0;
volatile int stop_sniffing = 0;
stored_packet_t stored_packets[MAX_PACKETS];
int stored_count = 0;

int main() {
    char device[256];
    
    // Register signal handler for graceful exit
    signal(SIGINT, signal_handler);
    
    printf("%s%s[C-Shark] The Command-Line Packet Predator%s\n", COLOR_BOLD, COLOR_CYAN, COLOR_RESET);
    printf("%s=%s==============================================%s\n", COLOR_BOLD, COLOR_YELLOW, COLOR_RESET);
    
    // Phase 1: Interface Discovery
    if (select_interface(device) != 0) {
        return 1;
    }
    
    // Phase 2-5: Main menu loop
    main_menu(device);
    
    // Cleanup
    free_stored_packets();
    
    return 0;
}