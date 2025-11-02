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
#include <link.h>

// Typedefs for the original memory allocation functions
typedef void *(*malloc_t)(size_t size);
typedef void (*free_t)(void *ptr);
typedef void *(*calloc_t)(size_t nmemb, size_t size);
typedef void *(*realloc_t)(void *ptr, size_t size);
typedef void *(*dlopen_t)(const char *filename, int flags);
typedef int (*dlclose_t)(void *handle);

// Pointers to the original memory allocation functions
static malloc_t real_malloc = NULL;
static free_t real_free = NULL;
static calloc_t real_calloc = NULL;
static realloc_t real_realloc = NULL;
static dlopen_t real_dlopen = NULL;
static dlclose_t real_dlclose = NULL;

// Use thread-local storage for the recursion guard
static __thread int in_hook = 0;
static int sock = -1;

// Add a mutex for thread-safe socket access
static pthread_mutex_t sock_lock = PTHREAD_MUTEX_INITIALIZER;

#define MAX_LIBS 256
static char processed_libs[MAX_LIBS][256];
static int processed_libs_count = 0;

static int has_been_processed(const char* libname) {
    for (int i = 0; i < processed_libs_count; i++) {
        if (strcmp(processed_libs[i], libname) == 0) {
            return 1;
        }
    }
    return 0;
}

static void add_to_processed(const char* libname) {
    if (processed_libs_count < MAX_LIBS) {
        strncpy(processed_libs[processed_libs_count++], libname, 255);
        processed_libs[processed_libs_count - 1][255] = '\0';
    }
}

static void send_initial_library_map() {
    FILE *fp = fopen("/proc/self/maps", "r");
    if (!fp) return;

    char line[1024];
    while (fgets(line, sizeof(line), fp)) {
        char* path_ptr = strchr(line, '/');
        if (path_ptr) {
            char* newline = strchr(path_ptr, '\n');
            if (newline) *newline = '\0';

            if (has_been_processed(path_ptr)) {
                continue;
            }

            unsigned long base_addr = (unsigned long)-1;
            FILE *fp2 = fopen("/proc/self/maps", "r");
            if (!fp2) continue;
            char line2[1024];
            while(fgets(line2, sizeof(line2), fp2)) {
                if (strstr(line2, path_ptr)) {
                    unsigned long current_start = strtoul(line2, NULL, 16);
                    if (current_start < base_addr) {
                        base_addr = current_start;
                    }
                }
            }
            fclose(fp2);

            if (base_addr != (unsigned long)-1) {
                pthread_mutex_lock(&sock_lock);
                char buffer[4096];
                int len = snprintf(buffer, sizeof(buffer), "D %s %lx\n", path_ptr, base_addr);
                send(sock, buffer, len, 0);
                pthread_mutex_unlock(&sock_lock);
                add_to_processed(path_ptr);
            }
        }
    }
    fclose(fp);
}

// Function to initialize the real function pointers and socket
static void init_hooks() {
    if (real_malloc == NULL) {
        real_malloc = dlsym(RTLD_NEXT, "malloc");
        real_free = dlsym(RTLD_NEXT, "free");
        real_calloc = dlsym(RTLD_NEXT, "calloc");
        real_realloc = dlsym(RTLD_NEXT, "realloc");
        real_dlopen = dlsym(RTLD_NEXT, "dlopen");
        real_dlclose = dlsym(RTLD_NEXT, "dlclose");
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
        send_initial_library_map();
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
        len += snprintf(buffer + len, sizeof(buffer) - len, " 0x%lx", (unsigned long)trace[i]);
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
        len += snprintf(buffer + len, sizeof(buffer) - len, " 0x%lx", (unsigned long)trace[i]);
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
        len += snprintf(buffer + len, sizeof(buffer) - len, " 0x%lx", (unsigned long)trace[i]);
    }
    len += snprintf(buffer + len, sizeof(buffer) - len, "\n");

    send(sock, buffer, len, 0);

    pthread_mutex_unlock(&sock_lock);

    in_hook = 0;
    return new_ptr;
}

void *dlopen(const char *filename, int flags) {
    if (real_dlopen == NULL) {
        init_hooks();
    }

    if (in_hook) {
        return real_dlopen(filename, flags);
    }

    in_hook = 1;
    void *handle = real_dlopen(filename, flags);

    if (handle && filename) {
        struct link_map *map;
        if (dlinfo(handle, RTLD_DI_LINKMAP, &map) == 0) {
            pthread_mutex_lock(&sock_lock);
            char buffer[4096];
            int len = snprintf(buffer, sizeof(buffer), "D %s %lx\n", map->l_name, map->l_addr);
            send(sock, buffer, len, 0);
            pthread_mutex_unlock(&sock_lock);
        }
    }

    in_hook = 0;
    return handle;
}

int dlclose(void *handle) {
    if (real_dlclose == NULL) {
        init_hooks();
    }

    if (in_hook) {
        return real_dlclose(handle);
    }

    in_hook = 1;

    if (handle) {
        struct link_map *map;
        if (dlinfo(handle, RTLD_DI_LINKMAP, &map) == 0) {
            pthread_mutex_lock(&sock_lock);
            char buffer[4096];
            int len = snprintf(buffer, sizeof(buffer), "X %s\n", map->l_name);
            send(sock, buffer, len, 0);
            pthread_mutex_unlock(&sock_lock);
        }
    }

    int result = real_dlclose(handle);
    in_hook = 0;
    return result;
}