#define _DEFAULT_SOURCE
#include "leanrfb_internal.h"
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <openssl/des.h>
#include <openssl/evp.h>
#include <unistd.h>
#include <errno.h>
#include <fcntl.h>
#include <sys/types.h>
#include <sys/socket.h>
#include <netinet/in.h>
#include <netinet/tcp.h>
#include <arpa/inet.h>
#include <poll.h>

// Forward declarations of internal helpers
static int set_nonblocking(int fd);
static int disable_nagle(int fd);
static int vnc_client_flush(vnc_client_t* client);
static int client_write_raw(vnc_client_t* client, const void* data, size_t len);
static void vnc_client_disconnect(vnc_server_t* server, vnc_client_t* client);
static void client_read_handler(vnc_server_t* server, vnc_client_t* client);
static void vnc_client_send_update(vnc_server_t* server, vnc_client_t* client);
static void vnc_send_audio_update(vnc_server_t* server, vnc_client_t* client);

// --- WebSocket and HTTP helpers ---

static const char* case_insensitive_strstr(const char* haystack, const char* needle) {
    if (!haystack || !needle) return NULL;
    size_t needle_len = strlen(needle);
    if (needle_len == 0) return haystack;
    
    for (; *haystack; haystack++) {
        size_t i;
        for (i = 0; i < needle_len; i++) {
            char h = haystack[i];
            char n = needle[i];
            if (h >= 'A' && h <= 'Z') h = h - 'A' + 'a';
            if (n >= 'A' && n <= 'Z') n = n - 'A' + 'a';
            if (h != n) break;
        }
        if (i == needle_len) {
            return haystack;
        }
    }
    return NULL;
}

static const char b64chars[] = "ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789+/";
static void base64_encode(const unsigned char* src, size_t len, char* out) {
    size_t i;
    for (i = 0; i < len; i += 3) {
        uint32_t val = (src[i] << 16) | ((i + 1 < len ? src[i+1] : 0) << 8) | (i + 2 < len ? src[i+2] : 0);
        *out++ = b64chars[(val >> 18) & 0x3F];
        *out++ = b64chars[(val >> 12) & 0x3F];
        *out++ = (i + 1 < len) ? b64chars[(val >> 6) & 0x3F] : '=';
        *out++ = (i + 2 < len) ? b64chars[val & 0x3F] : '=';
    }
    *out = '\0';
}

static void sha1_hash(const unsigned char* data, size_t len, unsigned char* md) {
    EVP_MD_CTX* ctx = EVP_MD_CTX_new();
    if (ctx) {
        EVP_DigestInit_ex(ctx, EVP_sha1(), NULL);
        EVP_DigestUpdate(ctx, data, len);
        unsigned int md_len;
        EVP_DigestFinal_ex(ctx, md, &md_len);
        EVP_MD_CTX_free(ctx);
    }
}

static int set_blocking(int fd) {
    int flags = fcntl(fd, F_GETFL, 0);
    if (flags < 0) return -1;
    return fcntl(fd, F_SETFL, flags & ~O_NONBLOCK);
}

static char* find_http_header(const char* request, const char* header_name) {
    char* pos = strstr(request, header_name);
    if (!pos) {
        char lower_name[64];
        size_t len = strlen(header_name);
        if (len < sizeof(lower_name)) {
            for (size_t i = 0; i < len; i++) {
                char c = header_name[i];
                if (c >= 'A' && c <= 'Z') c = c - 'A' + 'a';
                lower_name[i] = c;
            }
            lower_name[len] = '\0';
            pos = strstr(request, lower_name);
        }
    }
    if (!pos) return NULL;
    pos += strlen(header_name);
    while (*pos == ' ' || *pos == '\t') pos++;
    return pos;
}

static void get_header_value(const char* header_start, char* dest, size_t dest_len) {
    size_t i = 0;
    while (header_start[i] && header_start[i] != '\r' && header_start[i] != '\n' && i < dest_len - 1) {
        dest[i] = header_start[i];
        i++;
    }
    dest[i] = '\0';
}

// Extracts the request-target from an HTTP request line ("GET <path> HTTP/1.1").
// `request` must point at the start of the "GET " token.
static void get_request_path(const char* request, char* path_out, size_t path_out_len) {
    const char* start = request + 4; // skip "GET "
    size_t i = 0;
    while (start[i] && start[i] != ' ' && start[i] != '\r' && start[i] != '\n' && i < path_out_len - 1) {
        path_out[i] = start[i];
        i++;
    }
    path_out[i] = '\0';
}

static const char* content_type_for_file(const char* filename) {
    size_t len = strlen(filename);
    if (len >= 5 && strcmp(filename + len - 5, ".wasm") == 0) return "application/wasm";
    if (len >= 3 && strcmp(filename + len - 3, ".js") == 0) return "application/javascript";
    return "text/html";
}

// Maps an HTTP request path to the on-disk file (relative to the server's
// working directory) produced by `make wasm`. Returns NULL for unknown paths.
static const char* resolve_web_client_path(const char* req_path) {
    if (strcmp(req_path, "/") == 0 || strcmp(req_path, "/index.html") == 0) {
        return "vncview_web.html";
    }
    if (strcmp(req_path, "/vncview_web.js") == 0) return "vncview_web.js";
    if (strcmp(req_path, "/vncview_web.wasm") == 0) return "vncview_web.wasm";
    return NULL;
}

// Serves the WASM vncview web client (vncview_web.html/.js/.wasm, built via
// `make wasm`) as static files from the server's working directory. This is
// what a browser gets when it opens the VNC server's TCP port directly with a
// plain (non-WebSocket) HTTP GET.
static void serve_web_client(vnc_client_t* client, const char* req_path) {
    const char* filename = resolve_web_client_path(req_path);
    if (!filename) {
        const char* body = "404 Not Found\r\n";
        char hdr[128];
        int hdr_len = snprintf(hdr, sizeof(hdr),
            "HTTP/1.1 404 Not Found\r\nContent-Type: text/plain\r\nContent-Length: %zu\r\nConnection: close\r\n\r\n",
            strlen(body));
        send(client->fd, hdr, hdr_len, MSG_NOSIGNAL);
        send(client->fd, body, strlen(body), MSG_NOSIGNAL);
        return;
    }

    FILE* f = fopen(filename, "rb");
    if (!f) {
        const char* body =
            "VNC web client not built.\r\n"
            "Run `make wasm` (requires the Emscripten SDK) from the project root,\r\n"
            "then restart this server from the same directory.\r\n";
        char hdr[256];
        int hdr_len = snprintf(hdr, sizeof(hdr),
            "HTTP/1.1 503 Service Unavailable\r\nContent-Type: text/plain\r\nContent-Length: %zu\r\nConnection: close\r\n\r\n",
            strlen(body));
        send(client->fd, hdr, hdr_len, MSG_NOSIGNAL);
        send(client->fd, body, strlen(body), MSG_NOSIGNAL);
        return;
    }

    fseek(f, 0, SEEK_END);
    long fsize = ftell(f);
    fseek(f, 0, SEEK_SET);
    if (fsize < 0) {
        fclose(f);
        return;
    }

    char hdr[256];
    int hdr_len = snprintf(hdr, sizeof(hdr),
        "HTTP/1.1 200 OK\r\nContent-Type: %s\r\nContent-Length: %ld\r\nConnection: close\r\n\r\n",
        content_type_for_file(filename), fsize);
    send(client->fd, hdr, hdr_len, MSG_NOSIGNAL);

    char buf[65536];
    size_t n;
    while ((n = fread(buf, 1, sizeof(buf), f)) > 0) {
        size_t sent_total = 0;
        while (sent_total < n) {
            ssize_t sent = send(client->fd, buf + sent_total, n - sent_total, MSG_NOSIGNAL);
            if (sent <= 0) {
                fclose(f);
                return;
            }
            sent_total += (size_t)sent;
        }
    }
    fclose(f);
}

static int parse_websocket_frames(vnc_server_t* server, vnc_client_t* client) {
    (void)server;
    size_t processed = 0;
    while (processed < client->ws_read_len) {
        size_t remaining = client->ws_read_len - processed;
        if (remaining < 2) break;

        uint8_t* p = &client->ws_read_buf[processed];
        uint8_t opcode = p[0] & 0x0F;
        int has_mask = (p[1] & 0x80) != 0;
        uint64_t payload_len = p[1] & 0x7F;

        size_t header_len = 2;
        if (payload_len == 126) {
            if (remaining < 4) break;
            payload_len = ((uint64_t)p[2] << 8) | p[3];
            header_len = 4;
        } else if (payload_len == 127) {
            if (remaining < 10) break;
            payload_len = 0;
            for (int i = 0; i < 8; i++) {
                payload_len = (payload_len << 8) | p[2 + i];
            }
            header_len = 10;
        }

        size_t mask_len = has_mask ? 4 : 0;
        if (remaining < header_len + mask_len + payload_len) {
            break;
        }

        uint8_t* mask_key = has_mask ? (p + header_len) : NULL;
        uint8_t* payload = p + header_len + mask_len;

        if (opcode == 0x8) {
            return -1; // close/disconnect
        } else if (opcode == 0x9) {
            uint8_t pong_header[2] = {0x8A, 0x00};
            send(client->fd, pong_header, 2, MSG_NOSIGNAL);
        } else if (opcode == 0x1 || opcode == 0x2 || opcode == 0x0) {
            if (client->read_len + payload_len > VNC_READ_BUF_SIZE) {
                return -1; // buffer overflow
            }

            for (size_t i = 0; i < payload_len; i++) {
                uint8_t b = payload[i];
                if (has_mask) {
                    b ^= mask_key[i % 4];
                }
                client->read_buf[client->read_len++] = b;
            }
        }

        processed += header_len + mask_len + payload_len;
    }

    if (processed > 0) {
        memmove(client->ws_read_buf, &client->ws_read_buf[processed], client->ws_read_len - processed);
        client->ws_read_len -= processed;
    }
    return 0;
}


static unsigned long long get_time_ms(void) {
    struct timespec ts;
    clock_gettime(CLOCK_MONOTONIC, &ts);
    return (unsigned long long)ts.tv_sec * 1000 + ts.tv_nsec / 1000000;
}

// Shared with src/leanrfb_udp.c
unsigned long long vnc_get_time_ms(void) {
    return get_time_ms();
}

// --- Security helpers ---

// Constant-time memory comparison — prevents timing side-channel attacks.
// Returns 1 if all n bytes match, 0 otherwise.
static int mem_equal_ct(const uint8_t* a, const uint8_t* b, size_t n) {
    uint8_t diff = 0;
    for (size_t i = 0; i < n; i++) {
        diff |= a[i] ^ b[i];
    }
    return diff == 0;
}

// Fill buf with len cryptographically secure random bytes from /dev/urandom.
// Returns 0 on success, -1 on failure (caller must disconnect the client).
static int secure_random_bytes(uint8_t* buf, size_t len) {
    FILE* f = fopen("/dev/urandom", "rb");
    if (!f) return -1;
    size_t n = fread(buf, 1, len, f);
    fclose(f);
    return (n == len) ? 0 : -1;
}

// Returns 1 if ip is in the server's blocked list and the block has not expired.
// Expired entries are removed lazily.
static int ip_is_blocked(vnc_server_t* server, const char* ip) {
    time_t now = time(NULL);
    for (int i = 0; i < server->num_blocked_ips; ) {
        if (strcmp(server->blocked_ips[i].ip, ip) == 0) {
            if (now < server->blocked_ips[i].block_until) {
                return 1;
            }
            // Expired — swap with the last entry and shrink the list
            server->blocked_ips[i] = server->blocked_ips[--server->num_blocked_ips];
            return 0;
        }
        i++;
    }
    return 0;
}

// Record a failed authentication attempt; blocks the source IP when the threshold
// (VNC_AUTH_MAX_FAILS failures within VNC_AUTH_WINDOW_SEC seconds) is exceeded.
static void record_auth_failure(vnc_server_t* server, vnc_client_t* client) {
    time_t now = time(NULL);
    if (client->auth_fail_count == 0 ||
        now - client->auth_first_fail_time > VNC_AUTH_WINDOW_SEC) {
        client->auth_fail_count = 1;
        client->auth_first_fail_time = now;
    } else {
        client->auth_fail_count++;
    }

    if (client->auth_fail_count >= VNC_AUTH_MAX_FAILS) {
        fprintf(stderr, "[VNC SERVER] Blocking %s after %d auth failures\n",
                client->client_ip, client->auth_fail_count);
        fflush(stderr);
        int found = 0;
        for (int i = 0; i < server->num_blocked_ips; i++) {
            if (strcmp(server->blocked_ips[i].ip, client->client_ip) == 0) {
                server->blocked_ips[i].block_until = now + VNC_AUTH_BLOCK_SEC;
                found = 1;
                break;
            }
        }
        if (!found && server->num_blocked_ips < VNC_MAX_BLOCKED_IPS) {
            memcpy(server->blocked_ips[server->num_blocked_ips].ip,
                   client->client_ip, INET_ADDRSTRLEN);
            server->blocked_ips[server->num_blocked_ips].block_until = now + VNC_AUTH_BLOCK_SEC;
            server->num_blocked_ips++;
        }
    }
}

vnc_server_t* vnc_server_create(const vnc_server_config_t* config) {
    if (!config || config->width == 0 || config->height == 0) {
        return NULL;
    }

    int port = config->port <= 0 ? 5900 : config->port;
    int listen_fd = socket(AF_INET, SOCK_STREAM, 0);
    if (listen_fd < 0) {
        return NULL;
    }

    int reuse = 1;
    if (setsockopt(listen_fd, SOL_SOCKET, SO_REUSEADDR, &reuse, sizeof(reuse)) < 0) {
        close(listen_fd);
        return NULL;
    }

    struct sockaddr_in addr;
    memset(&addr, 0, sizeof(addr));
    addr.sin_family = AF_INET;
    addr.sin_port = htons(port);
    if (config->listen_host) {
        if (inet_pton(AF_INET, config->listen_host, &addr.sin_addr) <= 0) {
            close(listen_fd);
            return NULL;
        }
    } else {
        addr.sin_addr.s_addr = INADDR_ANY;
    }

    if (bind(listen_fd, (struct sockaddr*)&addr, sizeof(addr)) < 0) {
        close(listen_fd);
        return NULL;
    }

    if (listen(listen_fd, 10) < 0) {
        close(listen_fd);
        return NULL;
    }

    if (set_nonblocking(listen_fd) < 0) {
        close(listen_fd);
        return NULL;
    }

    // Best-effort UDP socket for the encrypted H.264 side-channel, bound to the same port
    // number as the TCP listener (UDP and TCP occupy independent namespaces, so this needs
    // no extra port to forward/allow through a firewall beyond the existing TCP port).
    // Failure to bind (e.g. UDP blocked, port in use by something else) is not fatal —
    // clients simply fall back to TCP-only H.264 delivery.
    int udp_fd = -1;
    if (!config->disable_udp_h264) {
        udp_fd = socket(AF_INET, SOCK_DGRAM, 0);
        if (udp_fd >= 0) {
            int udp_reuse = 1;
            setsockopt(udp_fd, SOL_SOCKET, SO_REUSEADDR, &udp_reuse, sizeof(udp_reuse));
            // A generous receive buffer absorbs bursts of client Hello/heartbeat datagrams
            // (e.g. several clients reconnecting at once) without the kernel dropping them.
            int rcvbuf = 4 * 1024 * 1024;
            setsockopt(udp_fd, SOL_SOCKET, SO_RCVBUF, &rcvbuf, sizeof(rcvbuf));
            if (bind(udp_fd, (struct sockaddr*)&addr, sizeof(addr)) < 0 ||
                set_nonblocking(udp_fd) < 0) {
                close(udp_fd);
                udp_fd = -1;
            }
        }
    }

    vnc_server_t* server = (vnc_server_t*)malloc(sizeof(vnc_server_t));
    if (!server) {
        close(listen_fd);
        if (udp_fd >= 0) close(udp_fd);
        return NULL;
    }

    server->listen_fd = listen_fd;
    server->udp_fd = udp_fd;
    server->disable_udp_h264 = config->disable_udp_h264;
    server->width = config->width;
    server->height = config->height;
    server->name = strdup(config->name ? config->name : "VNC Server");
    
    server->cols = (config->width + 15) / 16;
    server->rows = (config->height + 15) / 16;
    
    server->framebuffer = (uint32_t*)calloc((size_t)server->width * server->height, sizeof(uint32_t));
    server->server_dirty = (uint8_t*)calloc((size_t)server->cols * server->rows, sizeof(uint8_t));
    
    server->clients = NULL;
    server->cursor_pixels = NULL;
    server->cursor_w = 0;
    server->cursor_h = 0;
    server->cursor_xhot = 0;
    server->cursor_yhot = 0;
    server->on_key = config->on_key;
    server->on_pointer = config->on_pointer;
    server->on_resize_request = config->on_resize_request;
    server->on_clipboard = config->on_clipboard;
    server->user_data = config->user_data;
    server->password = config->password ? strdup(config->password) : NULL;
    server->max_clients = (config->max_clients > 0) ? config->max_clients : VNC_MAX_CLIENTS_DEFAULT;
    server->num_blocked_ips = 0;
    server->pfds_cache = NULL;
    server->pfds_cap = 0;
    server->websocket = config->websocket;
    server->allow_desktop_resize = config->allow_desktop_resize;
    server->enable_audio = config->enable_audio;

    if (!server->framebuffer || !server->server_dirty || !server->name) {
        vnc_server_destroy(server);
        return NULL;
    }

    return server;
}

void vnc_server_destroy(vnc_server_t* server) {
    if (!server) return;

    if (server->listen_fd >= 0) {
        close(server->listen_fd);
    }
    if (server->udp_fd >= 0) {
        close(server->udp_fd);
    }

    vnc_client_t* client = server->clients;
    while (client) {
        vnc_client_t* next = client->next;
        if (client->fd >= 0) close(client->fd);
        free(client->dirty_tiles);
        free(client);
        client = next;
    }

    free(server->framebuffer);
    free(server->server_dirty);
    free(server->cursor_pixels);
    free(server->password);
    free(server->name);
    free(server->pfds_cache);
    free(server);
}

int vnc_server_poll(vnc_server_t* server, int timeout_ms) {
    if (!server) return -1;

    unsigned long long now = get_time_ms();
    vnc_client_t* cl = server->clients;
    while (cl) {
        vnc_client_t* next = cl->next;
        if (cl->state == VNC_STATE_DETECT_WEBSOCKET) {
            if (now - cl->connect_time_ms >= 100) {
                cl->state = VNC_STATE_PROTOCOL_VERSION;
                const char* ver_str = "RFB 003.008\n";
                if (client_write_raw(cl, ver_str, 12) < 0) {
                    vnc_client_disconnect(server, cl);
                } else {
                    cl->state = VNC_STATE_WAIT_PROTOCOL_VERSION;
                }
            }
        }
        cl = next;
    }

    // Count clients + 1 for listening socket
    int client_count = 0;
    vnc_client_t* client = server->clients;
    while (client) {
        client_count++;
        client = client->next;
    }

    // Grow the cached pollfd array if needed (avoids malloc/free on every poll call).
    // Slot 0 is the TCP listener, slot 1 the UDP H.264 socket (fd may be -1, which poll()
    // ignores per POSIX), and client sockets start at slot 2.
    int needed = client_count + 2;
    if (needed > server->pfds_cap) {
        int new_cap = needed + 8; // over-allocate a bit to avoid frequent reallocs
        struct pollfd* new_pfds = realloc(server->pfds_cache, (size_t)new_cap * sizeof(struct pollfd));
        if (!new_pfds) return -1;
        server->pfds_cache = new_pfds;
        server->pfds_cap = new_cap;
    }
    struct pollfd* pfds = server->pfds_cache;

    pfds[0].fd = server->listen_fd;
    pfds[0].events = POLLIN;
    pfds[0].revents = 0;

    pfds[1].fd = server->udp_fd;
    pfds[1].events = POLLIN;
    pfds[1].revents = 0;

    int idx = 2;
    client = server->clients;
    while (client) {
        pfds[idx].fd = client->fd;
        pfds[idx].events = POLLIN;
        if (client->write_len > client->write_pos) {
            pfds[idx].events |= POLLOUT;
        }
        pfds[idx].revents = 0;
        idx++;
        client = client->next;
    }

    int ret = poll(pfds, (nfds_t)(client_count + 2), timeout_ms);
    if (ret < 0) {
        if (errno == EINTR) return 0;
        return -1;
    }

    if (pfds[1].revents & POLLIN) {
        vnc_udp_handle_incoming(server);
    }

    // 1. Check for new connections
    if (pfds[0].revents & POLLIN) {
        struct sockaddr_in client_addr;
        socklen_t client_len = sizeof(client_addr);
        int client_fd = accept(server->listen_fd, (struct sockaddr*)&client_addr, &client_len);
        if (client_fd >= 0) {
            // Extract remote IP before any further checks
            char ip_str[INET_ADDRSTRLEN];
            if (!inet_ntop(AF_INET, &client_addr.sin_addr, ip_str, sizeof(ip_str))) {
                snprintf(ip_str, sizeof(ip_str), "unknown");
            }

            if (client_count >= server->max_clients) {
                // Hard connection limit reached — reject silently
                fprintf(stderr, "[VNC SERVER] Connection limit (%d) reached, rejecting %s\n",
                        server->max_clients, ip_str);
                fflush(stderr);
                close(client_fd);
            } else if (ip_is_blocked(server, ip_str)) {
                // Source IP is temporarily blocked due to repeated auth failures
                fprintf(stderr, "[VNC SERVER] Rejected connection from blocked IP %s\n", ip_str);
                fflush(stderr);
                close(client_fd);
            } else if (set_nonblocking(client_fd) == 0 && disable_nagle(client_fd) == 0) {
                int sndbuf = 1024 * 1024;
                setsockopt(client_fd, SOL_SOCKET, SO_SNDBUF, (char*)&sndbuf, sizeof(sndbuf));
                vnc_client_t* new_client = (vnc_client_t*)calloc(1, sizeof(vnc_client_t));
                if (new_client) {
                    new_client->fd = client_fd;

                    snprintf(new_client->ip_addr, sizeof(new_client->ip_addr),
                             "%s:%d", ip_str, ntohs(client_addr.sin_port));
                    memcpy(new_client->client_ip, ip_str, INET_ADDRSTRLEN);

                    printf("[VNC SERVER] Client connected from %s\n", new_client->ip_addr);
                    fflush(stdout);

                    new_client->state = VNC_STATE_PROTOCOL_VERSION;
                    new_client->protocol_minor = 8;
                    // Initial format: same as server default (32-bit BGRA)
                    new_client->fmt = (vnc_pixel_fmt_t){32, 24, 0, 1, 255, 255, 255, 16, 8, 0, {0}};
                    new_client->format_custom = 0;
                    new_client->supports_hextile = 0;
                    new_client->supports_rich_cursor = 0;
                    new_client->send_cursor_update = 1;
                    // Matches QEMU's own VNC audio defaults, in case a client sends
                    // ENABLE before ever sending SET_FORMAT.
                    new_client->audio_wire_fmt = VNC_AUDIO_FMT_S16;
                    new_client->audio_channels = 2;
                    new_client->audio_freq = 44100;

                    new_client->write_cap = VNC_WRITE_BUF_INIT_SIZE;
                    new_client->write_buf = malloc(new_client->write_cap);
                    new_client->dirty_tiles = malloc((size_t)server->cols * server->rows);
                    if (new_client->write_buf && new_client->dirty_tiles) {
                        // Mark all tiles dirty on connect to send initial full screen
                        memset(new_client->dirty_tiles, 1, (size_t)server->cols * server->rows);

                        new_client->next = server->clients;
                        server->clients = new_client;

                        if (server->websocket) {
                            new_client->state = VNC_STATE_DETECT_WEBSOCKET;
                            new_client->connect_time_ms = get_time_ms();
                        } else {
                            // Send ProtocolVersion immediately
                            const char* ver_str = "RFB 003.008\n";
                            client_write_raw(new_client, ver_str, 12);
                            new_client->state = VNC_STATE_WAIT_PROTOCOL_VERSION;
                        }
                    } else {
                        free(new_client->write_buf);
                        free(new_client->dirty_tiles);
                        free(new_client);
                        close(client_fd);
                    }
                } else {
                    close(client_fd);
                }
            } else {
                close(client_fd);
            }
        }
    }

    // 2. Check client sockets
    idx = 2;
    client = server->clients;
    while (client) {
        vnc_client_t* next_client = client->next; // save next in case client disconnects
        
        if (pfds[idx].revents & POLLOUT) {
            vnc_client_flush(client);
        }
        
        if (pfds[idx].revents & POLLIN) {
            client_read_handler(server, client);
        } else if (pfds[idx].revents & (POLLERR | POLLHUP | POLLNVAL)) {
            vnc_client_disconnect(server, client);
        }
        
        idx++;
        client = next_client;
    }

    // 3. Process pending updates for connected, initialized clients
    client = server->clients;
    while (client) {
        if (client->state == VNC_STATE_NORMAL && client->update_requested) {
            vnc_client_send_update(server, client);
        }
        // Independent of the video FramebufferUpdateRequest cycle above — audio
        // should keep flowing even if the client is momentarily caught up on video.
        if (client->state == VNC_STATE_NORMAL) {
            vnc_send_audio_update(server, client);
        }
        client = client->next;
    }

    return 0;
}

void vnc_server_update_framebuffer(vnc_server_t* server, const uint32_t* fb_data) {
    if (!server || !fb_data) return;

    memset(server->server_dirty, 0, (size_t)server->cols * server->rows);

    for (int y = 0; y < server->height; y++) {
        size_t row_offset = y * (size_t)server->width;
        size_t row_bytes = (size_t)server->width * 4;

        if (memcmp(&server->framebuffer[row_offset], &fb_data[row_offset], row_bytes) != 0) {
            // Find which tiles are affected by changes in this row
            int r = y / 16;
            for (int c = 0; c < server->cols; c++) {
                int tile_idx = r * server->cols + c;
                int tx = c * 16;
                int tw = (server->width - tx < 16) ? (server->width - tx) : 16;

                if (!server->server_dirty[tile_idx]) {
                    if (memcmp(&server->framebuffer[row_offset + tx], &fb_data[row_offset + tx], (size_t)tw * 4) != 0) {
                        server->server_dirty[tile_idx] = 1;
                        vnc_client_t* cl = server->clients;
                        while (cl) {
                            cl->dirty_tiles[tile_idx] = 1;
                            cl = cl->next;
                        }
                    }
                }
            }
            // Now copy the whole scanline
            memcpy(&server->framebuffer[row_offset], &fb_data[row_offset], row_bytes);
        }
    }
}

void vnc_server_update_rect(vnc_server_t* server, const uint32_t* rect_data, uint16_t rx, uint16_t ry, uint16_t rw, uint16_t rh) {
    if (!server || !rect_data || rx + rw > server->width || ry + rh > server->height) return;

    for (int y = 0; y < rh; y++) {
        size_t dest_offset = (ry + y) * (size_t)server->width + rx;
        size_t src_offset = y * (size_t)rw;
        memcpy(&server->framebuffer[dest_offset], &rect_data[src_offset], (size_t)rw * 4);
    }

    vnc_server_mark_dirty(server, rx, ry, rw, rh);
}

void vnc_server_mark_dirty(vnc_server_t* server, uint16_t x, uint16_t y, uint16_t w, uint16_t h) {
    if (!server || w == 0 || h == 0) return;

    int start_col = x / 16;
    int end_col = (x + w - 1) / 16;
    int start_row = y / 16;
    int end_row = (y + h - 1) / 16;

    if (start_col < 0) start_col = 0;
    if (end_col >= server->cols) end_col = server->cols - 1;
    if (start_row < 0) start_row = 0;
    if (end_row >= server->rows) end_row = server->rows - 1;

    for (int r = start_row; r <= end_row; r++) {
        for (int c = start_col; c <= end_col; c++) {
            server->server_dirty[r * server->cols + c] = 1;
            vnc_client_t* client = server->clients;
            while (client) {
                client->dirty_tiles[r * server->cols + c] = 1;
                client = client->next;
            }
        }
    }
}

void vnc_server_resize_framebuffer(vnc_server_t* server, uint16_t new_width, uint16_t new_height) {
    if (!server || new_width == 0 || new_height == 0) return;
    if (server->width == new_width && server->height == new_height) return;

    int new_cols = (new_width + 15) / 16;
    int new_rows = (new_height + 15) / 16;

    uint32_t* new_fb = (uint32_t*)calloc((size_t)new_width * new_height, sizeof(uint32_t));
    uint8_t* new_dirty = (uint8_t*)calloc((size_t)new_cols * new_rows, sizeof(uint8_t));
    if (!new_fb || !new_dirty) {
        // Leave the server at its old (still valid) size rather than applying a
        // half-updated resize.
        free(new_fb);
        free(new_dirty);
        return;
    }

    free(server->framebuffer);
    free(server->server_dirty);
    server->framebuffer = new_fb;
    server->server_dirty = new_dirty;
    server->width = new_width;
    server->height = new_height;
    server->cols = new_cols;
    server->rows = new_rows;

    for (vnc_client_t* client = server->clients; client; client = client->next) {
        uint8_t* new_client_dirty = (uint8_t*)malloc((size_t)new_cols * new_rows);
        if (new_client_dirty) {
            memset(new_client_dirty, 1, (size_t)new_cols * new_rows); // full redraw at the new size
            free(client->dirty_tiles);
            client->dirty_tiles = new_client_dirty;
        }

        // Each client's H.264/VP9 encoder (if any) is sized for the old resolution —
        // drop it so vnc_send_video_update() lazily recreates it at the new size.
        if (client->h264_enc) {
            vnc_h264_encoder_destroy(client->h264_enc);
            client->h264_enc = NULL;
        }
        if (client->vp9_enc) {
            vnc_vp9_encoder_destroy(client->vp9_enc);
            client->vp9_enc = NULL;
        }
        // Force a fresh UDP handshake (and thus a fresh keyframe) rather than risk any
        // in-flight fragments/decoder state from the old resolution bleeding into the new
        // one.
        client->udp_setup_sent = 0;
        client->udp_ready = 0;
        client->force_keyframe_requested = 1;
        client->update_requested = 1;

        if (client->supports_ext_desktop_size) {
            client->pending_ext_desktop_size = 1;
            client->ext_desktop_reason = VNC_EDS_REASON_GENERIC;
            client->ext_desktop_status = VNC_EDS_STATUS_SUCCESS;
        }
    }
}

// Socket non-blocking helper
static int set_nonblocking(int fd) {
    int flags = fcntl(fd, F_GETFL, 0);
    if (flags < 0) return -1;
    return fcntl(fd, F_SETFL, flags | O_NONBLOCK);
}

// TCP_NODELAY helper
static int disable_nagle(int fd) {
    int flag = 1;
    return setsockopt(fd, IPPROTO_TCP, TCP_NODELAY, (char*)&flag, sizeof(int));
}

static int vnc_client_flush(vnc_client_t* client) {
    if (client->is_websocket && client->ws_handshake_done && client->write_len > 0 && client->write_pos == 0) {
        size_t len = client->write_len;
        size_t header_len = 0;
        uint8_t header[10];
        header[0] = 0x82; // FIN + Binary
        if (len <= 125) {
            header[1] = (uint8_t)len;
            header_len = 2;
        } else if (len <= 65535) {
            header[1] = 126;
            header[2] = (uint8_t)(len >> 8);
            header[3] = (uint8_t)(len & 0xFF);
            header_len = 4;
        } else {
            header[1] = 127;
            header[2] = (uint8_t)((len >> 56) & 0xFF);
            header[3] = (uint8_t)((len >> 48) & 0xFF);
            header[4] = (uint8_t)((len >> 40) & 0xFF);
            header[5] = (uint8_t)((len >> 32) & 0xFF);
            header[6] = (uint8_t)((len >> 24) & 0xFF);
            header[7] = (uint8_t)((len >> 16) & 0xFF);
            header[8] = (uint8_t)((len >> 8) & 0xFF);
            header[9] = (uint8_t)(len & 0xFF);
            header_len = 10;
        }

        if (client->write_cap < len + header_len) {
            size_t new_cap = client->write_cap * 2;
            if (new_cap < len + header_len) new_cap = len + header_len + 65536;
            uint8_t* new_buf = realloc(client->write_buf, new_cap);
            if (!new_buf) return -1;
            client->write_buf = new_buf;
            client->write_cap = new_cap;
        }

        memmove(client->write_buf + header_len, client->write_buf, len);
        memcpy(client->write_buf, header, header_len);
        client->write_len += header_len;
    }

    while (client->write_len > client->write_pos) {
        ssize_t n = send(client->fd, &client->write_buf[client->write_pos], client->write_len - client->write_pos, MSG_NOSIGNAL);
        if (n < 0) {
            if (errno == EAGAIN || errno == EWOULDBLOCK) {
                return 0; // standard non-blocking return
            }
            return -1; // real error
        }
        client->write_pos += n;
    }
    // Buffer fully flushed
    client->write_len = 0;
    client->write_pos = 0;
    return 0;
}

int client_ensure_write_space(vnc_client_t* client, size_t len) {
    if (client->write_cap - client->write_len < len) {
        vnc_client_flush(client);
        if (client->write_cap - client->write_len < len) {
            size_t new_cap = client->write_cap * 2;
            if (new_cap < client->write_len + len) {
                new_cap = client->write_len + len + 65536;
            }
            uint8_t* new_buf = realloc(client->write_buf, new_cap);
            if (!new_buf) return -1;
            client->write_buf = new_buf;
            client->write_cap = new_cap;
        }
    }
    return 0;
}

static int client_write_raw(vnc_client_t* client, const void* data, size_t len) {
    if (client_ensure_write_space(client, len) < 0) return -1;
    memcpy(&client->write_buf[client->write_len], data, len);
    client->write_len += len;
    return vnc_client_flush(client);
}

static int client_buf_append(vnc_client_t* client, const void* data, size_t len) {
    if (client_ensure_write_space(client, len) < 0) return -1;
    memcpy(&client->write_buf[client->write_len], data, len);
    client->write_len += len;
    return 0;
}

static void vnc_client_disconnect(vnc_server_t* server, vnc_client_t* client) {
    if (!server || !client) return;

    printf("[VNC SERVER] Client disconnected: %s\n", client->ip_addr);
    fflush(stdout);

    // Remove from linked list
    vnc_client_t* prev = NULL;
    vnc_client_t* curr = server->clients;
    while (curr) {
        if (curr == client) {
            if (prev) {
                prev->next = curr->next;
            } else {
                server->clients = curr->next;
            }
            break;
        }
        prev = curr;
        curr = curr->next;
    }

    if (client->fd >= 0) {
        close(client->fd);
    }
    if (client->h264_enc) {
        vnc_h264_encoder_destroy(client->h264_enc);
    }
    if (client->vp9_enc) {
        vnc_vp9_encoder_destroy(client->vp9_enc);
    }
    if (client->audio_capture) {
        vnc_audio_capture_stop(client->audio_capture);
    }
    free(client->dirty_tiles);
    memset(client->udp_key, 0, sizeof(client->udp_key)); // don't leave session key material in freed heap memory
    free(client);
}

#pragma GCC diagnostic push
#pragma GCC diagnostic ignored "-Wdeprecated-declarations"
static void vnc_encrypt_bytes(const char* password, const uint8_t* challenge, uint8_t* response) {
    unsigned char key[8] = {0};
    size_t pass_len = strlen(password);
    for (int i = 0; i < 8; i++) {
        unsigned char b = (i < (int)pass_len) ? (unsigned char)password[i] : 0;
        unsigned char rev = 0;
        for (int bit = 0; bit < 8; bit++) {
            if (b & (1 << bit)) {
                rev |= (1 << (7 - bit));
            }
        }
        key[i] = rev;
    }

    DES_cblock des_key;
    memcpy(&des_key, key, 8);
    DES_key_schedule schedule;
    DES_set_key(&des_key, &schedule);

    DES_cblock in1, out1;
    DES_cblock in2, out2;
    memcpy(&in1, challenge, 8);
    memcpy(&in2, challenge + 8, 8);

    DES_ecb_encrypt(&in1, &out1, &schedule, DES_ENCRYPT);
    DES_ecb_encrypt(&in2, &out2, &schedule, DES_ENCRYPT);

    memcpy(response, &out1, 8);
    memcpy(response + 8, &out2, 8);
}
#pragma GCC diagnostic pop

static void client_read_handler(vnc_server_t* server, vnc_client_t* client) {
    if (client->is_websocket && client->ws_handshake_done) {
        char buf[4096];
        ssize_t n = recv(client->fd, buf, sizeof(buf), 0);
        if (n <= 0) {
            if (n < 0 && (errno == EAGAIN || errno == EWOULDBLOCK)) return;
            goto disconnect;
        }

        if (client->ws_read_len + (size_t)n > VNC_READ_BUF_SIZE) goto disconnect;

        memcpy(&client->ws_read_buf[client->ws_read_len], buf, (size_t)n);
        client->ws_read_len += (size_t)n;

        if (parse_websocket_frames(server, client) < 0) {
            goto disconnect;
        }
    } else {
        char buf[4096];
        ssize_t n = recv(client->fd, buf, sizeof(buf), 0);
        if (n <= 0) {
            if (n < 0 && (errno == EAGAIN || errno == EWOULDBLOCK)) return;
            goto disconnect;
        }

        if (client->read_len + (size_t)n > VNC_READ_BUF_SIZE) goto disconnect;

        memcpy(&client->read_buf[client->read_len], buf, (size_t)n);
        client->read_len += (size_t)n;
    }

    size_t processed = 0;
    while (processed < client->read_len) {
        size_t remaining = client->read_len - processed;
        uint8_t* p = &client->read_buf[processed];

        if (client->state == VNC_STATE_DETECT_WEBSOCKET) {
            if (remaining >= 4) {
                if (memcmp(p, "GET ", 4) == 0) {
                    char* end_headers = strstr((char*)p, "\r\n\r\n");
                    if (!end_headers) {
                        break;
                    }
                    size_t headers_len = (end_headers + 4) - (char*)p;

                    char* upgrade = find_http_header((char*)p, "Upgrade:");
                    char* ws_key_hdr = find_http_header((char*)p, "Sec-WebSocket-Key:");

                    int is_ws_upgrade = 0;
                    if (upgrade && ws_key_hdr) {
                        char upgrade_val[64];
                        get_header_value(upgrade, upgrade_val, sizeof(upgrade_val));
                        if (case_insensitive_strstr(upgrade_val, "websocket")) {
                            is_ws_upgrade = 1;
                        }
                    }

                    if (is_ws_upgrade) {
                        char ws_key[128];
                        get_header_value(ws_key_hdr, ws_key, sizeof(ws_key));

                        char concat[256];
                        snprintf(concat, sizeof(concat), "%s258EAFA5-E914-47DA-95CA-C5AB0DC85B11", ws_key);

                        unsigned char sha1_res[20];
                        sha1_hash((unsigned char*)concat, strlen(concat), sha1_res);

                        char accept_key[128];
                        base64_encode(sha1_res, 20, accept_key);

                        char handshake_resp[512];
                        int resp_len = snprintf(handshake_resp, sizeof(handshake_resp),
                            "HTTP/1.1 101 Switching Protocols\r\n"
                            "Upgrade: websocket\r\n"
                            "Connection: Upgrade\r\n"
                            "Sec-WebSocket-Accept: %s\r\n"
                            "\r\n", accept_key);

                        if (send(client->fd, handshake_resp, resp_len, MSG_NOSIGNAL) < 0) {
                            goto disconnect;
                        }

                        client->is_websocket = 1;
                        client->ws_handshake_done = 1;
                        client->state = VNC_STATE_PROTOCOL_VERSION;

                        processed += headers_len;

                        const char* ver_str = "RFB 003.008\n";
                        client_write_raw(client, ver_str, 12);
                        client->state = VNC_STATE_WAIT_PROTOCOL_VERSION;
                    } else {
                        set_blocking(client->fd);

                        char req_path[256];
                        get_request_path((char*)p, req_path, sizeof(req_path));
                        serve_web_client(client, req_path);

                        goto disconnect;
                    }
                } else {
                    client->state = VNC_STATE_PROTOCOL_VERSION;
                    const char* ver_str = "RFB 003.008\n";
                    if (send(client->fd, ver_str, 12, MSG_NOSIGNAL) < 0) goto disconnect;
                    client->state = VNC_STATE_WAIT_PROTOCOL_VERSION;
                }
            } else {
                break;
            }
        }
        else if (client->state == VNC_STATE_WAIT_PROTOCOL_VERSION) {
            if (remaining < 12) break;
            if (memcmp(p, "RFB 003.", 8) != 0) goto disconnect;
            
            char minor_str[4] = {0};
            memcpy(minor_str, p + 8, 3);
            client->protocol_minor = atoi(minor_str);
            processed += 12;

            int has_pwd = (server->password && strlen(server->password) > 0);

            if (client->protocol_minor < 7) {
                if (has_pwd) {
                    // RFB 3.3: Send chosen security type directly (4 bytes: VncAuth = 2)
                    uint8_t sec_type[4] = {0, 0, 0, 2};
                    if (client_write_raw(client, sec_type, 4) < 0) goto disconnect;
                    
                    // Generate 16-byte random challenge (hard-fail if entropy unavailable)
                    if (secure_random_bytes(client->challenge, 16) < 0) goto disconnect;
                    
                    if (client_write_raw(client, client->challenge, 16) < 0) goto disconnect;
                    client->state = VNC_STATE_WAIT_VNC_AUTH_RESPONSE;
                } else {
                    // RFB 3.3: Send chosen security type directly (4 bytes: None = 1)
                    uint8_t sec_type[4] = {0, 0, 0, 1};
                    if (client_write_raw(client, sec_type, 4) < 0) goto disconnect;
                    client->state = VNC_STATE_WAIT_CLIENT_INIT;
                }
            } else {
                // RFB 3.7 or 3.8: Send list of security types (1 type: VncAuth=2 or None=1)
                uint8_t sec_types[2];
                sec_types[0] = 1;
                sec_types[1] = has_pwd ? 2 : 1;
                if (client_write_raw(client, sec_types, 2) < 0) goto disconnect;
                client->state = VNC_STATE_WAIT_SECURITY;
            }
        }
        else if (client->state == VNC_STATE_WAIT_SECURITY) {
            if (remaining < 1) break;
            uint8_t chosen_type = p[0];
            processed += 1;

            int has_pwd = (server->password && strlen(server->password) > 0);

            if (has_pwd) {
                if (chosen_type != 2) goto disconnect; // Must choose VncAuth (2)

                    // Generate 16-byte random challenge (hard-fail if entropy unavailable)
                    if (secure_random_bytes(client->challenge, 16) < 0) goto disconnect;

                if (client_write_raw(client, client->challenge, 16) < 0) goto disconnect;
                client->state = VNC_STATE_WAIT_VNC_AUTH_RESPONSE;
            } else {
                if (chosen_type != 1) goto disconnect; // Must choose None (1)
                
                if (client->protocol_minor >= 8) {
                    // RFB 3.8: Send SecurityResult (Success = 0)
                    uint8_t sec_res[4] = {0, 0, 0, 0};
                    if (client_write_raw(client, sec_res, 4) < 0) goto disconnect;
                }
                client->state = VNC_STATE_WAIT_CLIENT_INIT;
            }
        }
        else if (client->state == VNC_STATE_WAIT_VNC_AUTH_RESPONSE) {
            if (remaining < 16) break;
            processed += 16;

            // Generate expected response
            uint8_t expected[16];
            vnc_encrypt_bytes(server->password, client->challenge, expected);

            if (mem_equal_ct(expected, p, 16)) {
                // Send SecurityResult (Success = 0)
                uint8_t sec_res[4] = {0, 0, 0, 0};
                if (client_write_raw(client, sec_res, 4) < 0) goto disconnect;
                client->state = VNC_STATE_WAIT_CLIENT_INIT;
            } else {
                record_auth_failure(server, client);
                // Send SecurityResult (Failure = 1)
                uint8_t sec_res[4] = {0, 0, 0, 1};
                client_write_raw(client, sec_res, 4);
                goto disconnect;
            }
        }
        else if (client->state == VNC_STATE_WAIT_CLIENT_INIT) {
            if (remaining < 1) break;
            // shared-flag (ignored, but read)
            processed += 1;

            // ServerInit
            size_t name_len = strlen(server->name);
            size_t init_msg_size = 2 + 2 + 16 + 4 + name_len;
            uint8_t* init_msg = malloc(init_msg_size);
            if (!init_msg) goto disconnect;

            write_u16_be(init_msg + 0, server->width);
            write_u16_be(init_msg + 2, server->height);

            // BGRA 32-bit pixel format
            init_msg[4] = 32; // bits-per-pixel
            init_msg[5] = 24; // depth
            init_msg[6] = 0;  // big-endian
            init_msg[7] = 1;  // true-color
            write_u16_be(init_msg + 8, 255); // red-max
            write_u16_be(init_msg + 10, 255); // green-max
            write_u16_be(init_msg + 12, 255); // blue-max
            init_msg[14] = 16; // red-shift
            init_msg[15] = 8;  // green-shift
            init_msg[16] = 0;  // blue-shift
            memset(init_msg + 17, 0, 3); // padding

            write_u32_be(init_msg + 20, (uint32_t)name_len);
            memcpy(init_msg + 24, server->name, name_len);

            int write_res = client_write_raw(client, init_msg, init_msg_size);
            free(init_msg);
            if (write_res < 0) goto disconnect;

            client->state = VNC_STATE_NORMAL;
        }
        else if (client->state == VNC_STATE_NORMAL) {
            uint8_t msg_type = p[0];
            if (msg_type == 0) { // SetPixelFormat
                if (remaining < 20) break;
                {
                    uint8_t new_bpp = p[4];
                    if (new_bpp != 8 && new_bpp != 16 && new_bpp != 32) goto disconnect;
                    client->fmt.bits_per_pixel = new_bpp;
                }
                client->fmt.depth = p[5];
                client->fmt.big_endian_flag = p[6];
                client->fmt.true_color_flag = p[7];
                client->fmt.red_max = read_u16_be(p + 8);
                client->fmt.green_max = read_u16_be(p + 10);
                client->fmt.blue_max = read_u16_be(p + 12);
                client->fmt.red_shift = p[14];
                client->fmt.green_shift = p[15];
                client->fmt.blue_shift = p[16];

                vnc_pixel_fmt_t def_fmt = {32, 24, 0, 1, 255, 255, 255, 16, 8, 0, {0}};
                client->format_custom = !pixel_format_equal(&client->fmt, &def_fmt);
                processed += 20;
            }
            else if (msg_type == 2) { // SetEncodings
                if (remaining < 4) break;
                uint16_t num_encodings = read_u16_be(p + 2);
                if (remaining < 4 + (size_t)num_encodings * 4) break;

                client->supports_hextile = 0;
                client->supports_tight = 0;
                client->supports_rich_cursor = 0;
                client->supports_h264 = 0;
                client->supports_vp9 = 0;
                client->supports_udp = 0;
                int had_ext_desktop_size = client->supports_ext_desktop_size;
                client->supports_ext_desktop_size = 0;
                int had_audio = client->supports_audio;
                client->supports_audio = 0;
                printf("[VNC SERVER] Client supports encodings: ");
                for (int i = 0; i < num_encodings; i++) {
                    int32_t enc = (int32_t)read_u32_be(p + 4 + i * 4);
                    printf("%d ", enc);
                    if (enc == 5) {
                        client->supports_hextile = 1;
                    } else if (enc == 7) {
                        client->supports_tight = 1;
                    } else if (enc == 50) {
                        client->supports_h264 = 1;
                    } else if (enc == VNC_ENCODING_VP9) {
                        client->supports_vp9 = 1;
                    } else if (enc == VNC_ENCODING_UDP_SETUP) {
                        client->supports_udp = 1;
                    } else if (enc == VNC_ENCODING_EXT_DESKTOP_SIZE) {
                        client->supports_ext_desktop_size = 1;
                    } else if (enc == -239) {
                        client->supports_rich_cursor = 1;
                    } else if (enc == VNC_ENCODING_AUDIO) {
                        if (server->enable_audio) {
                            client->supports_audio = 1;
                        }
                    }
                }
                // Per the RFB ExtendedDesktopSize extension: announce the current size
                // (reason=Generic) the first time a client tells us it understands this
                // encoding, so it learns it may subsequently send SetDesktopSize.
                if (client->supports_ext_desktop_size && !had_ext_desktop_size) {
                    client->pending_ext_desktop_size = 1;
                    client->ext_desktop_reason = VNC_EDS_REASON_GENERIC;
                    client->ext_desktop_status = VNC_EDS_STATUS_SUCCESS;
                }
                // See src/leanrfb_audio.c: ack lets the client know it may now send
                // ENABLE/DISABLE/SET_FORMAT.
                if (client->supports_audio && !had_audio) {
                    client->pending_audio_ack = 1;
                }
                printf("\n");
                fflush(stdout);
                processed += 4 + (size_t)num_encodings * 4;
            }
            else if (msg_type == 3) { // FramebufferUpdateRequest
                if (remaining < 10) break;
                uint8_t incremental = p[1];
                uint16_t x = read_u16_be(p + 2);
                uint16_t y = read_u16_be(p + 4);
                uint16_t w = read_u16_be(p + 6);
                uint16_t h = read_u16_be(p + 8);

                client->update_requested = 1;
                client->update_incremental = incremental;
                client->req_x = x;
                client->req_y = y;
                client->req_w = w;
                client->req_h = h;
                processed += 10;
            }
            else if (msg_type == 4) { // KeyEvent
                if (remaining < 8) break;
                uint8_t down_flag = p[1];
                uint32_t keysym = read_u32_be(p + 4);
                if (server->on_key) {
                    server->on_key(server, client, keysym, down_flag, server->user_data);
                }
                processed += 8;
            }
            else if (msg_type == 5) { // PointerEvent
                if (remaining < 6) break;
                uint8_t button_mask = p[1];
                uint16_t x = read_u16_be(p + 2);
                uint16_t y = read_u16_be(p + 4);
                if (server->on_pointer) {
                    server->on_pointer(server, client, x, y, button_mask, server->user_data);
                }
                processed += 6;
            }
            else if (msg_type == 6) { // ClientCutText
                if (remaining < 8) break;
                uint32_t length = read_u32_be(p + 4);
                if (length > (uint32_t)VNC_CLIPBOARD_MAX_LEN) goto disconnect;
                if (remaining < 8 + (size_t)length) break;
                processed += 8 + (size_t)length;

                if (server->on_clipboard && length > 0) {
                    char* text = (char*)malloc(length + 1);
                    if (text) {
                        memcpy(text, p + 8, length);
                        text[length] = '\0';
                        server->on_clipboard(server, client, text, length, server->user_data);
                        free(text);
                    }
                }
            }
            else if (msg_type == VNC_MSG_SET_DESKTOP_SIZE) { // SetDesktopSize (RFB ExtendedDesktopSize extension)
                if (remaining < 8) break;
                uint16_t req_w = read_u16_be(p + 2);
                uint16_t req_h = read_u16_be(p + 4);
                uint8_t num_screens = p[6];
                size_t msg_len = 8 + (size_t)num_screens * 16;
                if (remaining < msg_len) break;
                processed += msg_len;

                // We don't need the client's proposed per-screen layout (this server only
                // ever has one screen) — the bytes were already consumed above so the
                // stream stays in sync regardless of what we do with them.
                uint16_t applied_w = req_w;
                uint16_t applied_h = req_h;
                int status;
                if (!server->allow_desktop_resize || !server->on_resize_request) {
                    status = VNC_RESIZE_PROHIBITED;
                } else if (req_w == 0 || req_h == 0 || num_screens == 0) {
                    status = VNC_RESIZE_INVALID_LAYOUT;
                } else {
                    status = server->on_resize_request(server, client, req_w, req_h,
                                                        &applied_w, &applied_h, server->user_data);
                }

                if (status == VNC_RESIZE_SUCCESS) {
                    vnc_server_resize_framebuffer(server, applied_w, applied_h);
                }

                client->pending_ext_desktop_size = 1;
                client->ext_desktop_reason = VNC_EDS_REASON_THIS_CLIENT;
                client->ext_desktop_status = status;

                // Per spec: on success, every OTHER client that understands this
                // extension is also told about the change; on failure, only the
                // requester hears about it.
                if (status == VNC_RESIZE_SUCCESS) {
                    for (vnc_client_t* other = server->clients; other; other = other->next) {
                        if (other != client && other->supports_ext_desktop_size) {
                            other->pending_ext_desktop_size = 1;
                            other->ext_desktop_reason = VNC_EDS_REASON_OTHER_CLIENT;
                            other->ext_desktop_status = VNC_EDS_STATUS_SUCCESS;
                        }
                    }
                }
            }
            else if (msg_type == 254) { // RequestKeyframe (custom extension, no payload)
                // Sent by the client when it has dropped a UDP frame it cannot recover
                // from (e.g. mid-GOP fragment loss); asks the encoder for a fresh IDR.
                client->force_keyframe_requested = 1;
                processed += 1;
            }
            else if (msg_type == VNC_MSG_CLIENT_QEMU) { // 255: QEMU extension wrapper
                if (remaining < 2) break;
                uint8_t qemu_sub = p[1];

                if (qemu_sub == VNC_MSG_CLIENT_QEMU_EXT_KEY_EVENT) {
                    // Not implemented server-side, but the fixed-size payload
                    // (down:u16 + keysym:u32 + keycode:u32) must still be consumed
                    // to keep the stream in sync.
                    if (remaining < 12) break;
                    processed += 12;
                }
                else if (qemu_sub == VNC_MSG_CLIENT_QEMU_AUDIO) {
                    if (!client->supports_audio) goto disconnect;
                    if (remaining < 4) break;
                    uint16_t audio_op = read_u16_be(p + 2);

                    if (audio_op == VNC_MSG_CLIENT_QEMU_AUDIO_ENABLE) {
                        processed += 4;
                        if (!client->audio_enabled) {
                            client->audio_capture = vnc_audio_capture_start(
                                client->audio_wire_fmt, client->audio_channels, client->audio_freq);
                            if (client->audio_capture) {
                                client->audio_enabled = 1;
                                client->pending_audio_begin = 1;
                            }
                        }
                    }
                    else if (audio_op == VNC_MSG_CLIENT_QEMU_AUDIO_DISABLE) {
                        processed += 4;
                        if (client->audio_enabled) {
                            vnc_audio_capture_stop(client->audio_capture);
                            client->audio_capture = NULL;
                            client->audio_enabled = 0;
                            client->pending_audio_end = 1;
                        }
                    }
                    else if (audio_op == VNC_MSG_CLIENT_QEMU_AUDIO_SET_FORMAT) {
                        if (remaining < 10) break;
                        uint8_t wire_fmt = p[4];
                        uint8_t channels = p[5];
                        uint32_t freq = read_u32_be(p + 6);
                        processed += 10;

                        if (wire_fmt <= VNC_AUDIO_FMT_S32 && (channels == 1 || channels == 2) &&
                            freq > 0 && freq <= 48000) {
                            client->audio_wire_fmt = wire_fmt;
                            client->audio_channels = channels;
                            client->audio_freq = (int)freq;
                            // Restart an already-running capture so the new format
                            // actually takes effect.
                            if (client->audio_enabled) {
                                vnc_audio_capture_stop(client->audio_capture);
                                client->audio_capture = vnc_audio_capture_start(wire_fmt, channels, (int)freq);
                                client->audio_enabled = client->audio_capture != NULL;
                            }
                        }
                    }
                    else {
                        goto disconnect;
                    }
                }
                else {
                    goto disconnect;
                }
            }
            else {
                goto disconnect;
            }
        }
    }

    if (processed > 0) {
        memmove(client->read_buf, &client->read_buf[processed], client->read_len - processed);
        client->read_len -= processed;
    }
    return;

disconnect:
    vnc_client_disconnect(server, client);
}

// Function-pointer table describing one video codec's encoder, so the UDP/TCP dispatch
// logic below (identical for every codec) only needs to be written once. See
// src/leanrfb_h264.c / src/leanrfb_vp9.c for the concrete implementations.
typedef struct {
    void* (*create)(int width, int height, int fps, int quality);
    int (*encode)(void* enc, const uint32_t* fb, uint8_t** out_data, int* out_len, int* is_keyframe, int* pts_out);
    void (*destroy)(void* enc);
    void (*force_keyframe)(void* enc);
    uint32_t rfb_encoding;  // TCP rectangle encoding id (50 = H.264, VNC_ENCODING_VP9 = VP9)
    uint8_t udp_codec_id;   // codec byte sent in the UDP setup payload (VNC_UDP_CODEC_*)
} vnc_video_ops_t;

static const vnc_video_ops_t vnc_h264_ops = {
    vnc_h264_encoder_create, vnc_h264_encoder_encode, vnc_h264_encoder_destroy,
    vnc_h264_encoder_force_keyframe, 50, VNC_UDP_CODEC_H264
};

static const vnc_video_ops_t vnc_vp9_ops = {
    vnc_vp9_encoder_create, vnc_vp9_encoder_encode, vnc_vp9_encoder_destroy,
    vnc_vp9_encoder_force_keyframe, VNC_ENCODING_VP9, VNC_UDP_CODEC_VP9
};

// Encode (lazily creating the encoder on first use) and deliver one video frame to a
// client, over UDP if that transport is live for this client, else over TCP. Handles the
// one-time UDP setup handshake and force-keyframe requests. `enc_slot` is the address of
// whichever of client->h264_enc / client->vp9_enc corresponds to `ops`.
static void vnc_send_video_update(vnc_server_t* server, vnc_client_t* client,
                                  void** enc_slot, const vnc_video_ops_t* ops) {
    int has_dirty = 0;
    for (int i = 0; i < server->cols * server->rows; i++) {
        if (client->dirty_tiles[i]) {
            has_dirty = 1;
            break;
        }
    }
    if (!has_dirty) {
        return;
    }

    if (!*enc_slot) {
        *enc_slot = ops->create(server->width, server->height, 30, 80);
        if (!*enc_slot) return;
    }

    // One-time handshake: hand the client a fresh random key + connection id for the
    // encrypted UDP transport over the already-authenticated TCP control channel.
    // See docs/custom/rfb_h264_udp_extension.md.
    if (client->supports_udp && !client->udp_setup_sent && server->udp_fd >= 0) {
        uint8_t key[VNC_UDP_KEY_LEN];
        uint8_t cid[VNC_UDP_CID_LEN];
        if (secure_random_bytes(key, sizeof(key)) == 0 && secure_random_bytes(cid, sizeof(cid)) == 0) {
            memcpy(client->udp_key, key, sizeof(key));
            memcpy(client->udp_cid, cid, sizeof(cid));
            client->udp_ready = 0;
            client->udp_send_ctr = 0;
            client->udp_frame_id = 0;
            client->udp_recv_replay.highest = 0;
            client->udp_recv_replay.bitmap = 0;

            struct sockaddr_in local_addr;
            socklen_t local_len = sizeof(local_addr);
            uint16_t udp_port = 0;
            if (getsockname(server->udp_fd, (struct sockaddr*)&local_addr, &local_len) == 0) {
                udp_port = ntohs(local_addr.sin_port);
            }

            uint8_t setup_payload[2 + VNC_UDP_CID_LEN + VNC_UDP_KEY_LEN + 1];
            write_u16_be(setup_payload, udp_port);
            memcpy(setup_payload + 2, cid, VNC_UDP_CID_LEN);
            memcpy(setup_payload + 2 + VNC_UDP_CID_LEN, key, VNC_UDP_KEY_LEN);
            setup_payload[2 + VNC_UDP_CID_LEN + VNC_UDP_KEY_LEN] = ops->udp_codec_id;

            uint8_t header[4] = {0, 0, 0, 1};
            uint8_t r_header[12];
            write_u16_be(r_header + 0, 0);
            write_u16_be(r_header + 2, 0);
            write_u16_be(r_header + 4, server->width);
            write_u16_be(r_header + 6, server->height);
            write_u32_be(r_header + 8, VNC_ENCODING_UDP_SETUP);

            if (client_buf_append(client, header, 4) == 0 &&
                client_buf_append(client, r_header, 12) == 0 &&
                client_buf_append(client, setup_payload, sizeof(setup_payload)) == 0) {
                client->udp_setup_sent = 1;
                vnc_client_flush(client);
            }
        }
    }

    if (client->force_keyframe_requested) {
        ops->force_keyframe(*enc_slot);
        client->force_keyframe_requested = 0;
    }

    uint8_t* video_data = NULL;
    int video_len = 0;
    int is_key = 0;
    int pts = 0;
    int enc_ret = ops->encode(*enc_slot, server->framebuffer, &video_data, &video_len, &is_key, &pts);
    if (enc_ret == 0 && video_len == 0) {
        // Not an error — low-delay hardware encoders can take a couple of frames
        // before their first packet comes out. But if this persists well beyond
        // that, the encoder is stuck (bad driver/format/config) rather than just
        // warming up, and previously this failed completely silently — no crash,
        // no frames, no indication why. Surface it once so it's diagnosable.
        client->video_stall_frames++;
        if (client->video_stall_frames == 60) {
            fprintf(stderr,
                "[VNC SERVER] Warning: video encoder has produced no output for %d consecutive frames "
                "(encode() keeps returning success with 0 bytes) — likely a stuck/misconfigured hardware "
                "encoder. Try disabling UDP/hardware encoding or check driver logs.\n",
                client->video_stall_frames);
        }
    } else if (enc_ret == 0) {
        client->video_stall_frames = 0;
    }
    if (enc_ret == 0 && video_len > 0) {
        // Any keyframe the encoder actually emits is by definition self-contained (no
        // dependency on prior frames) and safe to reset the client's decoder onto. This
        // used to instead check `pts == 1` as a proxy for "the first real output packet,
        // assuming exactly one frame of encoder lookahead latency" — but encoder lookahead
        // varies (0, 1, or more frames depending on codec/backend), so that heuristic
        // could miss the frame that was actually the true first keyframe, leaving the
        // client's decoder permanently unprimed (a black screen) until the next GOP
        // boundary keyframe, sometimes seconds later.
        uint32_t flags = is_key ? 2 : 0;

        int udp_active = client->supports_udp && client->udp_ready && server->udp_fd >= 0 &&
                         (get_time_ms() - client->udp_last_recv_ms < VNC_UDP_LIVENESS_TIMEOUT_MS);

        if (udp_active && vnc_udp_send_video_frame(server, client, video_data, video_len, (int)flags) == 0) {
            memset(client->dirty_tiles, 0, (size_t)server->cols * server->rows);
            client->update_requested = 0;
            return;
        }

        // TCP fallback: UDP not (yet) negotiated/live for this client, or the frame
        // was too large to fragment over UDP.
        uint8_t header[4];
        header[0] = 0;
        header[1] = 0;
        write_u16_be(header + 2, 1);
        if (client_buf_append(client, header, 4) < 0) return;

        uint8_t r_header[12];
        write_u16_be(r_header + 0, 0);
        write_u16_be(r_header + 2, 0);
        write_u16_be(r_header + 4, server->width);
        write_u16_be(r_header + 6, server->height);
        write_u32_be(r_header + 8, ops->rfb_encoding);
        if (client_buf_append(client, r_header, 12) < 0) return;

        uint8_t p_header[8];
        write_u32_be(p_header + 0, (uint32_t)video_len);
        write_u32_be(p_header + 4, flags);

        if (client_buf_append(client, p_header, 8) < 0) return;
        if (client_buf_append(client, video_data, video_len) < 0) return;

        memset(client->dirty_tiles, 0, (size_t)server->cols * server->rows);
        client->update_requested = 0;
        vnc_client_flush(client);
    }
}

static void vnc_client_send_update(vnc_server_t* server, vnc_client_t* client) {
    if (client->write_len > client->write_pos) return;

    client->write_len = 0;
    client->write_pos = 0;

    // Live desktop resize notification (RFB ExtendedDesktopSize extension). See
    // docs/custom/rfb_desktop_resize_extension.md.
    if (client->pending_ext_desktop_size) {
        uint8_t header[4] = {0, 0, 0, 1};
        uint8_t r_header[12];
        write_u16_be(r_header + 0, (uint16_t)client->ext_desktop_reason);
        write_u16_be(r_header + 2, (uint16_t)client->ext_desktop_status);
        write_u16_be(r_header + 4, server->width);
        write_u16_be(r_header + 6, server->height);
        write_u32_be(r_header + 8, (uint32_t)VNC_ENCODING_EXT_DESKTOP_SIZE);

        // Payload: numberOfScreens(1) + pad(3), then one 16-byte screen structure
        // describing the single (whole-framebuffer) screen this server exposes.
        uint8_t payload[20];
        payload[0] = 1;
        payload[1] = payload[2] = payload[3] = 0;
        write_u32_be(payload + 4, 0);                 // screen id
        write_u16_be(payload + 8, 0);                 // x
        write_u16_be(payload + 10, 0);                // y
        write_u16_be(payload + 12, server->width);
        write_u16_be(payload + 14, server->height);
        write_u32_be(payload + 16, 0);                // flags

        if (client_buf_append(client, header, 4) == 0 &&
            client_buf_append(client, r_header, 12) == 0 &&
            client_buf_append(client, payload, sizeof(payload)) == 0) {
            client->pending_ext_desktop_size = 0;
            vnc_client_flush(client);

            if (client->write_len > client->write_pos) {
                return;
            }
            client->write_len = 0;
            client->write_pos = 0;
        }
    }

    if (client->send_cursor_update && client->supports_rich_cursor && server->cursor_pixels) {
        size_t mask_bytes_per_row = (server->cursor_w + 7) / 8;
        size_t bpp = get_pixel_size(&client->fmt, client->format_custom);
        size_t cursor_size = 4 + 12 + (size_t)server->cursor_w * server->cursor_h * bpp + (size_t)server->cursor_h * mask_bytes_per_row;
        
        if (client_ensure_write_space(client, cursor_size) == 0) {
            // Write FramebufferUpdate header (1 rect)
            client->write_buf[client->write_len++] = 0;
            client->write_buf[client->write_len++] = 0;
            client->write_buf[client->write_len++] = 0;
            client->write_buf[client->write_len++] = 1;
            
            // Write rect header
            write_u16_be(&client->write_buf[client->write_len], server->cursor_xhot);
            client->write_len += 2;
            write_u16_be(&client->write_buf[client->write_len], server->cursor_yhot);
            client->write_len += 2;
            write_u16_be(&client->write_buf[client->write_len], server->cursor_w);
            client->write_len += 2;
            write_u16_be(&client->write_buf[client->write_len], server->cursor_h);
            client->write_len += 2;
            write_u32_be(&client->write_buf[client->write_len], (uint32_t)-239);
            client->write_len += 4;
            
            // Convert and write pixels
            uint8_t* p = &client->write_buf[client->write_len];
            for (int i = 0; i < server->cursor_w * server->cursor_h; i++) {
                convert_pixel(server->cursor_pixels[i], p, &client->fmt);
                p += bpp;
            }
            client->write_len += (size_t)server->cursor_w * server->cursor_h * bpp;
            
            // Compute and write mask
            uint8_t* mask = &client->write_buf[client->write_len];
            memset(mask, 0, (size_t)server->cursor_h * mask_bytes_per_row);
            for (int y = 0; y < server->cursor_h; y++) {
                uint8_t* row_mask = mask + y * mask_bytes_per_row;
                for (int x = 0; x < server->cursor_w; x++) {
                    uint32_t pixel = server->cursor_pixels[y * server->cursor_w + x];
                    uint8_t alpha = (uint8_t)(pixel >> 24);
                    if (alpha > 0) {
                        row_mask[x / 8] |= (1 << (7 - (x % 8)));
                    }
                }
            }
            client->write_len += (size_t)server->cursor_h * mask_bytes_per_row;
            client->send_cursor_update = 0;
            
            vnc_client_flush(client);
            
            if (client->write_len > client->write_pos) {
                return;
            }
            client->write_len = 0;
            client->write_pos = 0;
        }
    }

    if (client->supports_h264) {
        vnc_send_video_update(server, client, &client->h264_enc, &vnc_h264_ops);
        return;
    }
    if (client->supports_vp9) {
        vnc_send_video_update(server, client, &client->vp9_enc, &vnc_vp9_ops);
        return;
    }

    int req_start_col = client->req_x / 16;
    int req_end_col = (client->req_x + client->req_w - 1) / 16;
    int req_start_row = client->req_y / 16;
    int req_end_row = (client->req_y + client->req_h - 1) / 16;

    if (req_start_col < 0) req_start_col = 0;
    if (req_end_col >= server->cols) req_end_col = server->cols - 1;
    if (req_start_row < 0) req_start_row = 0;
    if (req_end_row >= server->rows) req_end_row = server->rows - 1;

    if (!client->update_incremental) {
        for (int r = req_start_row; r <= req_end_row; r++) {
            for (int c = req_start_col; c <= req_end_col; c++) {
                client->dirty_tiles[r * server->cols + c] = 1;
            }
        }
        client->update_incremental = 1;
    }

    typedef struct {
        uint16_t x, y, w, h;
    } rect_t;
    rect_t update_rects[4096];
    int rect_count = 0;

    for (int r = req_start_row; r <= req_end_row; r++) {
        int c = req_start_col;
        while (c <= req_end_col) {
            if (client->dirty_tiles[r * server->cols + c]) {
                int start_c = c;
                while (c <= req_end_col && client->dirty_tiles[r * server->cols + c]) {
                    c++;
                }
                int count = c - start_c;

                uint16_t rx = start_c * 16;
                uint16_t ry = r * 16;
                uint16_t rw = count * 16;
                uint16_t rh = 16;

                if (rx < client->req_x) {
                    rw -= (client->req_x - rx);
                    rx = client->req_x;
                }
                if (rx + rw > client->req_x + client->req_w) {
                    rw = (client->req_x + client->req_w) - rx;
                }
                if (ry < client->req_y) {
                    rh -= (client->req_y - ry);
                    ry = client->req_y;
                }
                if (ry + rh > client->req_y + client->req_h) {
                    rh = (client->req_y + client->req_h) - ry;
                }

                if (rx + rw > server->width) rw = server->width - rx;
                if (ry + rh > server->height) rh = server->height - ry;

                if (rw > 0 && rh > 0) {
                    update_rects[rect_count++] = (rect_t){rx, ry, rw, rh};
                    if (rect_count >= 4096) break;
                }
            } else {
                c++;
            }
        }
        if (rect_count >= 4096) break;
    }

    // Vertical coalescing pass
    int merged = 1;
    while (merged) {
        merged = 0;
        for (int i = 0; i < rect_count; i++) {
            if (update_rects[i].h == 0) continue;
            for (int j = i + 1; j < rect_count; j++) {
                if (update_rects[j].h == 0) continue;
                if (update_rects[i].x == update_rects[j].x &&
                    update_rects[i].w == update_rects[j].w &&
                    update_rects[i].y + update_rects[i].h == update_rects[j].y) {
                    update_rects[i].h += update_rects[j].h;
                    update_rects[j].h = 0;
                    merged = 1;
                }
            }
        }
    }

    // Pack active rectangles
    int active_rects = 0;
    for (int i = 0; i < rect_count; i++) {
        if (update_rects[i].h > 0) {
            if (i != active_rects) {
                update_rects[active_rects] = update_rects[i];
            }
            active_rects++;
        }
    }
    rect_count = active_rects;

    if (rect_count == 0) {
        // Keep update_requested = 1 so we retry when the framebuffer changes
        return;
    }

    // Batch all headers and pixel data into the write buffer; flush once at the end.
    // Using client_buf_append avoids a send() syscall for every rect header.
    uint8_t header[4];
    header[0] = 0;
    header[1] = 0;
    write_u16_be(header + 2, (uint16_t)rect_count);
    if (client_buf_append(client, header, 4) < 0) return;

    for (int i = 0; i < rect_count; i++) {
        rect_t rect = update_rects[i];

        uint8_t r_header[12];
        write_u16_be(r_header + 0, rect.x);
        write_u16_be(r_header + 2, rect.y);
        write_u16_be(r_header + 4, rect.w);
        write_u16_be(r_header + 6, rect.h);

        int encoding = 0; // Raw
        if (client->supports_tight) {
            encoding = 7; // Tight (JPEG)
        } else if (client->supports_hextile) {
            encoding = 5; // Hextile
        }
        write_u32_be(r_header + 8, (uint32_t)encoding);

        if (client_buf_append(client, r_header, 12) < 0) return;

        if (encoding == 7) {
            uint8_t* jpeg_buf = NULL;
            unsigned long jpeg_size = 0;
            const uint32_t* src = &server->framebuffer[rect.y * server->width + rect.x];

            if (compress_jpeg(src, rect.w, rect.h, server->width, &jpeg_buf, &jpeg_size, 80) < 0) {
                return;
            }

            if (client_ensure_write_space(client, 1 + 3 + jpeg_size) < 0) {
                free(jpeg_buf);
                return;
            }

            // Tight JPEG compression-control byte (0x90)
            client->write_buf[client->write_len++] = 0x90;

            // Compact representation of JPEG size
            if (jpeg_size < 128) {
                client->write_buf[client->write_len++] = (uint8_t)jpeg_size;
            } else if (jpeg_size < 16384) {
                client->write_buf[client->write_len++] = (uint8_t)((jpeg_size & 0x7F) | 0x80);
                client->write_buf[client->write_len++] = (uint8_t)((jpeg_size >> 7) & 0x7F);
            } else {
                client->write_buf[client->write_len++] = (uint8_t)((jpeg_size & 0x7F) | 0x80);
                client->write_buf[client->write_len++] = (uint8_t)(((jpeg_size >> 7) & 0x7F) | 0x80);
                client->write_buf[client->write_len++] = (uint8_t)((jpeg_size >> 14) & 0xFF);
            }

            memcpy(&client->write_buf[client->write_len], jpeg_buf, jpeg_size);
            client->write_len += jpeg_size;

            free(jpeg_buf);
        } else if (encoding == 5) {
            if (vnc_encode_hextile(client, server->framebuffer, server->width, server->height, rect.x, rect.y, rect.w, rect.h) < 0) {
                return;
            }
        } else {
            // Raw encoding: pre-ensure space for the entire rect before the row loop
            // to avoid repeated capacity checks and potential reallocs per row.
            int bpp = get_pixel_size(&client->fmt, client->format_custom);
            size_t rect_bytes = (size_t)rect.w * (size_t)rect.h * (size_t)bpp;
            if (client_ensure_write_space(client, rect_bytes) < 0) return;

            for (int y = 0; y < rect.h; y++) {
                const uint32_t* src_ptr = &server->framebuffer[(rect.y + y) * server->width + rect.x];
                uint8_t* p = &client->write_buf[client->write_len];
                if (!client->format_custom) {
                    memcpy(p, src_ptr, (size_t)rect.w * 4);
                    client->write_len += (size_t)rect.w * 4;
                } else {
                    for (int x = 0; x < rect.w; x++) {
                        convert_pixel(src_ptr[x], p, &client->fmt);
                        p += bpp;
                    }
                    client->write_len += (size_t)rect.w * (size_t)bpp;
                }
            }
        }

        // Clear dirty flags for this rect using memset per tile-row (faster than nested loop)
        int start_c = rect.x / 16;
        int end_c   = (rect.x + rect.w - 1) / 16;
        int start_r = rect.y / 16;
        int end_r   = (rect.y + rect.h - 1) / 16;
        for (int r = start_r; r <= end_r; r++) {
            memset(&client->dirty_tiles[r * server->cols + start_c], 0,
                   (size_t)(end_c - start_c + 1));
        }
    }

    client->update_requested = 0;

    // Flush the entire frame update in one go (minimizes send() syscalls)
    vnc_client_flush(client);
}

// QEMU audio extension output (see src/leanrfb_audio.c). Sends the feature-ack
// pseudo-rect and BEGIN/END/DATA messages queued by client_read_handler and the
// capture thread. All writes here go through client_buf_append + one flush per
// call, same as vnc_client_send_update, to avoid emitting a WebSocket frame
// header mid-message (see the vnc_client struct's audio field comments).
static void vnc_send_audio_update(vnc_server_t* server, vnc_client_t* client) {
    if (client->write_len > client->write_pos) return; // previous write still draining

    int wrote_anything = 0;

    if (client->pending_audio_ack) {
        uint8_t header[4] = {0, 0, 0, 1};
        uint8_t r_header[12];
        write_u16_be(r_header + 0, 0);
        write_u16_be(r_header + 2, 0);
        write_u16_be(r_header + 4, server->width);
        write_u16_be(r_header + 6, server->height);
        write_u32_be(r_header + 8, (uint32_t)VNC_ENCODING_AUDIO);

        if (client_buf_append(client, header, 4) == 0 &&
            client_buf_append(client, r_header, 12) == 0) {
            client->pending_audio_ack = 0;
            wrote_anything = 1;
        }
    }

    if (client->pending_audio_begin) {
        uint8_t msg[4];
        msg[0] = VNC_MSG_SERVER_QEMU;
        msg[1] = VNC_MSG_SERVER_QEMU_AUDIO;
        write_u16_be(msg + 2, VNC_MSG_SERVER_QEMU_AUDIO_BEGIN);
        if (client_buf_append(client, msg, 4) == 0) {
            client->pending_audio_begin = 0;
            wrote_anything = 1;
        }
    }

    if (client->pending_audio_end) {
        uint8_t msg[4];
        msg[0] = VNC_MSG_SERVER_QEMU;
        msg[1] = VNC_MSG_SERVER_QEMU_AUDIO;
        write_u16_be(msg + 2, VNC_MSG_SERVER_QEMU_AUDIO_END);
        if (client_buf_append(client, msg, 4) == 0) {
            client->pending_audio_end = 0;
            wrote_anything = 1;
        }
    }

    if (client->audio_enabled && client->audio_capture) {
        // Sized to drain the entire capture ring (see VNC_AUDIO_RING_CAP in
        // leanrfb_audio.c) in one call, rather than trickling it out a fixed
        // 4KB at a time regardless of how much is actually backlogged — that
        // throttling was the main source of growing audio delay under any
        // poll-loop hiccup (screen capture/encode taking a beat, etc).
        uint8_t chunk[128 * 1024];
        size_t got = vnc_audio_capture_drain(client->audio_capture, chunk, sizeof(chunk));
        if (got > 0) {
            uint8_t header[8];
            header[0] = VNC_MSG_SERVER_QEMU;
            header[1] = VNC_MSG_SERVER_QEMU_AUDIO;
            write_u16_be(header + 2, VNC_MSG_SERVER_QEMU_AUDIO_DATA);
            write_u32_be(header + 4, (uint32_t)got);

            if (client_buf_append(client, header, 8) == 0 &&
                client_buf_append(client, chunk, got) == 0) {
                wrote_anything = 1;
            }
        }
    }

    if (wrote_anything) {
        vnc_client_flush(client);
    }
}

void vnc_server_set_cursor(vnc_server_t* server, const uint32_t* pixels, uint16_t w, uint16_t h, uint16_t xhot, uint16_t yhot) {
    if (!server) return;

    free(server->cursor_pixels);
    server->cursor_pixels = NULL;
    server->cursor_w = w;
    server->cursor_h = h;
    server->cursor_xhot = xhot;
    server->cursor_yhot = yhot;

    if (w > 0 && h > 0 && pixels) {
        server->cursor_pixels = (uint32_t*)malloc((size_t)w * h * sizeof(uint32_t));
        if (server->cursor_pixels) {
            memcpy(server->cursor_pixels, pixels, (size_t)w * h * sizeof(uint32_t));
        }
    }

    // Notify all connected clients that support RichCursor to download the new cursor shape
    vnc_client_t* client = server->clients;
    while (client) {
        client->send_cursor_update = 1;
        client = client->next;
    }
}

int vnc_server_has_clients(const vnc_server_t* server) {
    return server && server->clients != NULL;
}

void vnc_server_send_clipboard(vnc_server_t* server, const char* text, uint32_t len) {
    if (!server || !text || len == 0) return;

    vnc_client_t* client = server->clients;
    while (client) {
        if (client->state == VNC_STATE_NORMAL) {
            uint8_t header[8];
            header[0] = 3; // ServerCutText
            header[1] = 0;
            header[2] = 0;
            header[3] = 0;
            write_u32_be(header + 4, len);

            if (client_ensure_write_space(client, 8 + len) == 0) {
                memcpy(&client->write_buf[client->write_len], header, 8);
                client->write_len += 8;
                memcpy(&client->write_buf[client->write_len], text, len);
                client->write_len += len;
                vnc_client_flush(client);
            }
        }
        client = client->next;
    }
}
