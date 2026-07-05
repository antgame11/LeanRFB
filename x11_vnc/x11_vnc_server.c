#define _DEFAULT_SOURCE
#include "leanrfb.h"
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <X11/extensions/Xfixes.h>
#include <unistd.h>
#include <sys/ipc.h>
#include <sys/shm.h>
#include <X11/Xlib.h>
#include <X11/Xutil.h>
#include <X11/keysym.h>
#include <X11/extensions/XShm.h>
#include <X11/extensions/XTest.h>

typedef struct {
    Display* dpy;
    uint8_t last_buttons;
} x11_ctx_t;

static void on_key(vnc_server_t* server, vnc_client_t* client, uint32_t keysym, int down, void* user_data) {
    (void)server;
    (void)client;
    x11_ctx_t* ctx = (x11_ctx_t*)user_data;
    if (!ctx || !ctx->dpy) return;

    // Translate VNC keysym to X11 keycode
    KeyCode code = XKeysymToKeycode(ctx->dpy, (KeySym)keysym);
    if (code != 0) {
        XTestFakeKeyEvent(ctx->dpy, code, down ? True : False, CurrentTime);
        XFlush(ctx->dpy);
    }
}

static void on_pointer(vnc_server_t* server, vnc_client_t* client, uint16_t x, uint16_t y, uint8_t button_mask, void* user_data) {
    (void)server;
    (void)client;
    x11_ctx_t* ctx = (x11_ctx_t*)user_data;
    if (!ctx || !ctx->dpy) return;

    // Inject motion event (absolute position)
    XTestFakeMotionEvent(ctx->dpy, -1, x, y, CurrentTime);

    // Detect button state changes (buttons 1 to 5)
    uint8_t diff = button_mask ^ ctx->last_buttons;
    for (int b = 1; b <= 5; b++) {
        uint8_t mask = (1 << (b - 1));
        if (diff & mask) {
            int down = (button_mask & mask) ? True : False;
            XTestFakeButtonEvent(ctx->dpy, b, down, CurrentTime);
        }
    }
    ctx->last_buttons = button_mask;

    XFlush(ctx->dpy);
}

static void copy_ximage_to_fb(XImage* img, uint32_t* fb) {
    int width = img->width;
    int height = img->height;
    int bpp = img->bits_per_pixel;
    
    if (bpp == 32) {
        unsigned long r_mask = img->red_mask;
        unsigned long g_mask = img->green_mask;
        unsigned long b_mask = img->blue_mask;
        
        // Fast path: if XImage is standard BGRA format (B=0x000000FF, G=0x0000FF00, R=0x00FF0000)
        if (r_mask == 0x00FF0000 && g_mask == 0x0000FF00 && b_mask == 0x000000FF) {
            for (int y = 0; y < height; y++) {
                const uint32_t* src = (const uint32_t*)(img->data + y * img->bytes_per_line);
                memcpy(&fb[y * width], src, (size_t)width * 4);
            }
        } else {
            // Calculate shifts
            int r_shift = 0, g_shift = 0, b_shift = 0;
            unsigned long temp;
            
            temp = r_mask; while (temp && !(temp & 1)) { temp >>= 1; r_shift++; }
            temp = g_mask; while (temp && !(temp & 1)) { temp >>= 1; g_shift++; }
            temp = b_mask; while (temp && !(temp & 1)) { temp >>= 1; b_shift++; }
            
            for (int y = 0; y < height; y++) {
                const uint32_t* src = (const uint32_t*)(img->data + y * img->bytes_per_line);
                uint32_t* dst = &fb[y * width];
                for (int x = 0; x < width; x++) {
                    uint32_t pixel = src[x];
                    uint8_t r = (uint8_t)((pixel & r_mask) >> r_shift);
                    uint8_t g = (uint8_t)((pixel & g_mask) >> g_shift);
                    uint8_t b = (uint8_t)((pixel & b_mask) >> b_shift);
                    dst[x] = (uint32_t)b | ((uint32_t)g << 8) | ((uint32_t)r << 16);
                }
            }
        }
    } else {
        // Slow fallback for other bpps using XGetPixel
        for (int y = 0; y < height; y++) {
            uint32_t* dst = &fb[y * width];
            for (int x = 0; x < width; x++) {
                unsigned long pixel = XGetPixel(img, x, y);
                uint8_t r = (uint8_t)((pixel & img->red_mask) >> 16);
                uint8_t g = (uint8_t)((pixel & img->green_mask) >> 8);
                uint8_t b = (uint8_t)(pixel & img->blue_mask);
                dst[x] = (uint32_t)b | ((uint32_t)g << 8) | ((uint32_t)r << 16);
            }
        }
    }
}

#include <time.h>

static unsigned long long get_time_ms(void) {
    struct timespec ts;
    clock_gettime(CLOCK_MONOTONIC, &ts);
    return (unsigned long long)ts.tv_sec * 1000 + ts.tv_nsec / 1000000;
}

int main(int argc, char* argv[]) {
    int port = 5900;
    char config_password[256] = {0};
    char config_listen_host[64] = {0};
    char config_name[128] = {0};
    int max_clients = 16;
    int websocket_enabled = 0;
    int udp_enabled = 1;
    const char* password = NULL;
    const char* listen_host = "0.0.0.0";
    const char* display_name = "leanrfb X11 Server";

    // Try parsing config file first
    FILE* cf = fopen("x11_vnc_server.conf", "r");
    if (!cf) {
        cf = fopen("x11_vnc/x11_vnc_server.conf", "r");
    }
    if (cf) {
        char line[256];
        while (fgets(line, sizeof(line), cf)) {
            // Strip comments
            char* comment = strchr(line, '#');
            if (comment) *comment = '\0';
            
            // Trim whitespace
            char* key = line;
            while (*key == ' ' || *key == '\t') key++;
            char* end = key + strlen(key) - 1;
            while (end > key && (*end == ' ' || *end == '\t' || *end == '\n' || *end == '\r')) {
                *end = '\0';
                end--;
            }
            if (*key == '\0') continue;

            char* value = strchr(key, '=');
            if (!value) continue;
            *value = '\0';
            value++;
            while (*value == ' ' || *value == '\t') value++;

            if (strcmp(key, "port") == 0) {
                port = atoi(value);
            } else if (strcmp(key, "listen_host") == 0) {
                strncpy(config_listen_host, value, sizeof(config_listen_host) - 1);
                listen_host = config_listen_host;
            } else if (strcmp(key, "display_name") == 0) {
                strncpy(config_name, value, sizeof(config_name) - 1);
                display_name = config_name;
            } else if (strcmp(key, "password") == 0) {
                strncpy(config_password, value, sizeof(config_password) - 1);
                password = config_password;
            } else if (strcmp(key, "max_clients") == 0) {
                max_clients = atoi(value);
            } else if (strcmp(key, "websocket") == 0) {
                if (strcmp(value, "y") == 0 || strcmp(value, "yes") == 0 || strcmp(value, "1") == 0 || strcmp(value, "true") == 0) {
                    websocket_enabled = 1;
                } else {
                    websocket_enabled = 0;
                }
            } else if (strcmp(key, "enable_udp") == 0) {
                if (strcmp(value, "y") == 0 || strcmp(value, "yes") == 0 || strcmp(value, "1") == 0 || strcmp(value, "true") == 0) {
                    udp_enabled = 1;
                } else {
                    udp_enabled = 0;
                }
            }
        }
        fclose(cf);
    }

    // Command-line arguments override configuration file
    if (argc > 1) {
        port = atoi(argv[1]);
        if (port < 1 || port > 65535) {
            fprintf(stderr, "Error: Invalid port '%s'. Must be in range 1-65535.\n", argv[1]);
            return 1;
        }
    }
    if (argc > 2) {
        strncpy(config_password, argv[2], sizeof(config_password) - 1);
        password = config_password;
        // Zero out the argv entry so the password is not visible in /proc/<pid>/cmdline
        volatile char* p = argv[2];
        while (*p) { *p++ = '\0'; }
    }

    // Open connection to X server
    Display* dpy = XOpenDisplay(NULL);
    if (!dpy) {
        fprintf(stderr, "Error: Could not open X display. Is DISPLAY environment variable set?\n");
        return 1;
    }

    int screen_num = DefaultScreen(dpy);
    int width = DisplayWidth(dpy, screen_num);
    int height = DisplayHeight(dpy, screen_num);
    Window root = RootWindow(dpy, screen_num);

    printf("Sharing X11 screen (resolution %dx%d) on port %d...\n", width, height, port);
    if (password) {
        printf("Authentication enabled (using VncAuth protocol).\n");
    } else {
        printf("Authentication disabled (no password configured).\n");
    }
    printf("Encrypted UDP transport for H.264 video: %s\n", udp_enabled ? "enabled" : "disabled (TCP only)");

    // Context for callbacks
    x11_ctx_t ctx;
    ctx.dpy = dpy;
    ctx.last_buttons = 0;

    // Create VNC server
    vnc_server_config_t config;
    memset(&config, 0, sizeof(config));
    config.port = port;
    config.listen_host = listen_host;
    config.name = display_name;
    config.width = (uint16_t)width;
    config.height = (uint16_t)height;
    config.password = password;
    config.max_clients = max_clients;
    config.websocket = websocket_enabled;
    config.disable_udp_h264 = !udp_enabled;
    config.on_key = on_key;
    config.on_pointer = on_pointer;
    config.user_data = &ctx;

    vnc_server_t* server = vnc_server_create(&config);
    if (!server) {
        fprintf(stderr, "Error: Failed to create VNC server\n");
        XCloseDisplay(dpy);
        return 1;
    }

    // Setup MIT-SHM (Shared Memory)
    int has_shm = 0;
    XShmSegmentInfo shminfo;
    XImage* shm_img = NULL;

    if (XShmQueryExtension(dpy)) {
        shm_img = XShmCreateImage(dpy, DefaultVisual(dpy, screen_num),
                                  (unsigned int)DefaultDepth(dpy, screen_num),
                                  ZPixmap, NULL, &shminfo, (unsigned int)width, (unsigned int)height);
        if (shm_img) {
            shminfo.shmid = shmget(IPC_PRIVATE, (size_t)shm_img->bytes_per_line * (size_t)shm_img->height, IPC_CREAT | 0600);
            if (shminfo.shmid >= 0) {
                shminfo.shmaddr = shm_img->data = shmat(shminfo.shmid, 0, 0);
                if (shminfo.shmaddr != (char*)-1) {
                    shminfo.readOnly = False;
                    if (XShmAttach(dpy, &shminfo)) {
                        has_shm = 1;
                        printf("MIT-SHM Shared Memory extension enabled successfully.\n");
                    } else {
                        shmdt(shminfo.shmaddr);
                        shmctl(shminfo.shmid, IPC_RMID, 0);
                        XDestroyImage(shm_img);
                        shm_img = NULL;
                    }
                } else {
                    shmctl(shminfo.shmid, IPC_RMID, 0);
                    XDestroyImage(shm_img);
                    shm_img = NULL;
                }
            } else {
                XDestroyImage(shm_img);
                shm_img = NULL;
            }
        }
    }

    if (!has_shm) {
        printf("MIT-SHM Shared Memory extension not available. Falling back to standard XGetImage (slower).\n");
    }

    uint32_t* fb = malloc((size_t)width * (size_t)height * sizeof(uint32_t));
    if (!fb) {
        fprintf(stderr, "Error: Memory allocation failed for framebuffer\n");
        if (has_shm) {
            XShmDetach(dpy, &shminfo);
            shmdt(shminfo.shmaddr);
            shmctl(shminfo.shmid, IPC_RMID, 0);
            XDestroyImage(shm_img);
        }
        vnc_server_destroy(server);
        XCloseDisplay(dpy);
        return 1;
    }

    int xfixes_event_base = 0;
    int xfixes_error_base = 0;
    int has_xfixes = XFixesQueryExtension(dpy, &xfixes_event_base, &xfixes_error_base);
    unsigned long last_cursor_serial = 0;

    printf("Server is ready. Connect using a VNC viewer (e.g. 0.0.0.0:%d)\n", port);

    unsigned long long last_frame_time = get_time_ms();

    while (1) {
        unsigned long long now = get_time_ms();
        unsigned long long elapsed = now - last_frame_time;

        // Target 60 FPS (16 ms frame time)
        if (elapsed >= 16) {
            // Skip capture entirely when no clients are connected — saves the full
            // XShm read + pixel conversion + tile comparison cost at idle.
            if (vnc_server_has_clients(server)) {
                // Capture screen
                if (has_shm) {
                    XShmGetImage(dpy, root, shm_img, 0, 0, AllPlanes);
                    copy_ximage_to_fb(shm_img, fb);
                } else {
                    XImage* img = XGetImage(dpy, root, 0, 0, (unsigned int)width, (unsigned int)height, AllPlanes, ZPixmap);
                    if (img) {
                        copy_ximage_to_fb(img, fb);
                        XDestroyImage(img);
                    }
                }

                // Send screen updates
                vnc_server_update_framebuffer(server, fb);

                // Update cursor shape if it changed
                if (has_xfixes) {
                    XFixesCursorImage* cursor = XFixesGetCursorImage(dpy);
                    if (cursor) {
                        if (cursor->cursor_serial != last_cursor_serial) {
                            uint32_t* c_pixels = malloc((size_t)cursor->width * cursor->height * sizeof(uint32_t));
                            if (c_pixels) {
                                for (int i = 0; i < cursor->width * cursor->height; i++) {
                                    c_pixels[i] = (uint32_t)cursor->pixels[i];
                                }
                                vnc_server_set_cursor(server, c_pixels, cursor->width, cursor->height, cursor->xhot, cursor->yhot);
                                free(c_pixels);
                            }
                            last_cursor_serial = cursor->cursor_serial;
                        }
                        XFree(cursor);
                    }
                }
            }

            last_frame_time = now;
            elapsed = 0;
        }

        // Poll VNC events with remaining time in the 16ms window
        unsigned long long sleep_time = 16 - elapsed;
        if (sleep_time > 16) sleep_time = 0;

        vnc_server_poll(server, (int)sleep_time);
    }

    // Cleanup (unreachable in infinite loop, but good practice)
    free(fb);
    if (has_shm) {
        XShmDetach(dpy, &shminfo);
        shmdt(shminfo.shmaddr);
        shmctl(shminfo.shmid, IPC_RMID, 0);
        XDestroyImage(shm_img);
    }
    vnc_server_destroy(server);
    XCloseDisplay(dpy);
    return 0;
}
