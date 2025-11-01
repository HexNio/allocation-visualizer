#define _GNU_SOURCE
#include <stdio.h>
#include <dlfcn.h>
#include <unistd.h>
#include <sys/socket.h>
#include <netinet/in.h>
#include <arpa/inet.h>
#include <string.h>
#include <execinfo.h>
#include <stdlib.h>
#include <pthread.h>
#include <time.h>

// Typedefs for the original memory allocation functions
typedef void *(*malloc_t)(size_t size);
typedef void (*free_t)(void *ptr);
typedef void *(*calloc_t)(size_t nmemb, size_t size);
typedef void *(*realloc_t)(void *ptr, size_t size);

// Pointers to the original memory allocation functions
static malloc_t real_malloc = NULL;
static free_t real_free = NULL;
static calloc_t real_calloc = NULL;
static realloc_t real_realloc = NULL;

// Use thread-local storage for the recursion guard
static __thread int in_hook = 0;
static int sock = -1;
static unsigned long base_addr = 0;
static unsigned long end_addr = 0;

// Add a mutex for thread-safe socket access
static pthread_mutex_t sock_lock = PTHREAD_MUTEX_INITIALIZER;


unsigned long get_base_address(unsigned long *end) {
    FILE *fp;
    char line[1024];
    unsigned long start = 0;

    fp = fopen("/proc/self/maps", "r");
    if (fp == NULL) {
        return 0;
    }

    while (fgets(line, sizeof(line), fp) != NULL) {
        if (strstr(line, "r-xp") != NULL) {
            char *end_ptr;
            start = strtoul(line, &end_ptr, 16);
            *end = strtoul(end_ptr + 1, &end_ptr, 16);
            break;
        }
    }

    fclose(fp);
    return start;
}

// Function to initialize the real function pointers and socket
static void init_hooks() {
    if (real_malloc == NULL) {
        real_malloc = dlsym(RTLD_NEXT, "malloc");
        real_free = dlsym(RTLD_NEXT, "free");
        real_calloc = dlsym(RTLD_NEXT, "calloc");
        real_realloc = dlsym(RTLD_NEXT, "realloc");
        base_addr = get_base_address(&end_addr);
    }

    if (sock == -1) {
        struct sockaddr_in serv_addr;
        sock = socket(AF_INET, SOCK_STREAM, 0);
        if (sock < 0) {
            return;
        }

        serv_addr.sin_family = AF_INET;
        serv_addr.sin_port = htons(12345);

        if (inet_pton(AF_INET, RECEIVER_IP, &serv_addr.sin_addr) <= 0) {
            return;
        }

        if (connect(sock, (struct sockaddr *)&serv_addr, sizeof(serv_addr)) < 0) {
            return;
        }
    }
}

void *malloc(size_t size) {
    if (real_malloc == NULL) {
        init_hooks();
    }

    if (in_hook) {
        return real_malloc(size);
    }

    in_hook = 1;
    void *ptr = real_malloc(size);
    
    pthread_mutex_lock(&sock_lock);
    
    char buffer[4096];
    struct timespec ts;
    clock_gettime(CLOCK_MONOTONIC, &ts);
    int len = snprintf(buffer, sizeof(buffer), "M 0x%lx %zu %ld %ld", (unsigned long)ptr, size, ts.tv_sec, ts.tv_nsec);
    
    void *trace[16];
    int trace_size = backtrace(trace, 16);
    for (int i = 0; i < trace_size; ++i) {
        unsigned long addr = (unsigned long)trace[i];
        if (addr >= base_addr && addr < end_addr) {
            len += snprintf(buffer + len, sizeof(buffer) - len, " 0x%lx", (addr - base_addr));
        }
    }
    len += snprintf(buffer + len, sizeof(buffer) - len, "\n");

    send(sock, buffer, len, 0);
    
    pthread_mutex_unlock(&sock_lock);
    
    in_hook = 0;
    return ptr;
}

void free(void *ptr) {
    if (real_free == NULL) {
        init_hooks();
    }

    if (in_hook) {
        real_free(ptr);
        return;
    }

    in_hook = 1;
    
    pthread_mutex_lock(&sock_lock);
    
    char buffer[128];
    struct timespec ts;
    clock_gettime(CLOCK_MONOTONIC, &ts);
    int len = snprintf(buffer, sizeof(buffer), "F 0x%lx %ld %ld\n", (unsigned long)ptr, ts.tv_sec, ts.tv_nsec);
    send(sock, buffer, len, 0);

    pthread_mutex_unlock(&sock_lock);

    real_free(ptr);
    in_hook = 0;
}

void *calloc(size_t nmemb, size_t size) {
    if (real_calloc == NULL) {
        init_hooks();
    }

    if (in_hook) {
        return real_calloc(nmemb, size);
    }

    in_hook = 1;
    void *ptr = real_calloc(nmemb, size);

    pthread_mutex_lock(&sock_lock);

    char buffer[4096];
    struct timespec ts;
    clock_gettime(CLOCK_MONOTONIC, &ts);
    int len = snprintf(buffer, sizeof(buffer), "C 0x%lx %zu %zu %ld %ld", (unsigned long)ptr, nmemb, size, ts.tv_sec, ts.tv_nsec);

    void *trace[16];
    int trace_size = backtrace(trace, 16);
    for (int i = 0; i < trace_size; ++i) {
        unsigned long addr = (unsigned long)trace[i];
        if (addr >= base_addr && addr < end_addr) {
            len += snprintf(buffer + len, sizeof(buffer) - len, " 0x%lx", (addr - base_addr));
        }
    }
    len += snprintf(buffer + len, sizeof(buffer) - len, "\n");

    send(sock, buffer, len, 0);

    pthread_mutex_unlock(&sock_lock);

    in_hook = 0;
    return ptr;
}

void *realloc(void *ptr, size_t size) {
    if (real_realloc == NULL) {
        init_hooks();
    }

    if (in_hook) {
        return real_realloc(ptr, size);
    }

    in_hook = 1;
    void *new_ptr = real_realloc(ptr, size);

    pthread_mutex_lock(&sock_lock);

    char buffer[4096];
    struct timespec ts;
    clock_gettime(CLOCK_MONOTONIC, &ts);
    int len = snprintf(buffer, sizeof(buffer), "R 0x%lx 0x%lx %zu %ld %ld", (unsigned long)ptr, (unsigned long)new_ptr, size, ts.tv_sec, ts.tv_nsec);

    void *trace[16];
    int trace_size = backtrace(trace, 16);
    for (int i = 0; i < trace_size; ++i) {
        unsigned long addr = (unsigned long)trace[i];
        if (addr >= base_addr && addr < end_addr) {
            len += snprintf(buffer + len, sizeof(buffer) - len, " 0x%lx", (addr - base_addr));
        }
    }
    len += snprintf(buffer + len, sizeof(buffer) - len, "\n");

    send(sock, buffer, len, 0);

    pthread_mutex_unlock(&sock_lock);

    in_hook = 0;
    return new_ptr;
}