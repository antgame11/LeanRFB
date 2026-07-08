#define _DEFAULT_SOURCE
#include "leanrfb.h"
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <signal.h>
#include <X11/extensions/Xfixes.h>
#include <unistd.h>
#include <sys/ipc.h>
#include <sys/shm.h>
#include <X11/Xlib.h>
#include <X11/Xutil.h>
#include <X11/keysym.h>
#include <X11/extensions/XShm.h>
#include <X11/extensions/XTest.h>
#include <X11/extensions/Xrandr.h>
#include <X11/Xatom.h>

typedef struct {
    Display* dpy;
    Window root;
    int screen_num;
    uint8_t last_buttons;

    // Capture state — mutable because a live desktop resize (see on_resize_request
    // below) reallocates all of this at runtime, not just once at startup.
    uint32_t* fb;
    int width;
    int height;
    int has_shm;
    XShmSegmentInfo shminfo;
    XImage* shm_img;
    Window selection_win;
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

static char* g_clipboard_text = NULL;
static size_t g_clipboard_len = 0;

static void on_clipboard(vnc_server_t* server, vnc_client_t* client, const char* text, uint32_t len, void* user_data) {
    (void)server;
    (void)client;
    x11_ctx_t* ctx = (x11_ctx_t*)user_data;
    if (!ctx || !ctx->dpy || ctx->selection_win == None) return;

    free(g_clipboard_text);
    g_clipboard_text = malloc(len + 1);
    if (g_clipboard_text) {
        memcpy(g_clipboard_text, text, len);
        g_clipboard_text[len] = '\0';
        g_clipboard_len = len;
    } else {
        g_clipboard_len = 0;
    }

    Atom clipboard_atom = XInternAtom(ctx->dpy, "CLIPBOARD", False);
    XSetSelectionOwner(ctx->dpy, clipboard_atom, ctx->selection_win, CurrentTime);
    XSetSelectionOwner(ctx->dpy, XA_PRIMARY, ctx->selection_win, CurrentTime);
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
        }
        // Fast path for standard RGBA format (R=0x000000FF, G=0x0000FF00, B=0x00FF0000)
        else if (r_mask == 0x000000FF && g_mask == 0x0000FF00 && b_mask == 0x00FF0000) {
            for (int y = 0; y < height; y++) {
                const uint32_t* src = (const uint32_t*)(img->data + y * img->bytes_per_line);
                uint32_t* dst = &fb[y * width];
                for (int x = 0; x < width; x++) {
                    uint32_t pixel = src[x];
                    dst[x] = ((pixel & 0xFF) << 16) | (pixel & 0xFF00) | ((pixel & 0xFF0000) >> 16);
                }
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

// Free whatever capture buffers ctx currently holds (MIT-SHM segment/image and the
// plain fb buffer), leaving it in a state where setup_capture_buffers() can be called
// again. Safe to call on a freshly-zeroed ctx (all fields NULL/0).
static void teardown_capture_buffers(x11_ctx_t* ctx) {
    if (ctx->has_shm) {
        XShmDetach(ctx->dpy, &ctx->shminfo);
        shmdt(ctx->shminfo.shmaddr);
        shmctl(ctx->shminfo.shmid, IPC_RMID, 0);
        XDestroyImage(ctx->shm_img);
        ctx->shm_img = NULL;
        ctx->has_shm = 0;
    }
    free(ctx->fb);
    ctx->fb = NULL;
}

// (Re)allocate the capture buffers (MIT-SHM image + plain fb) for a width x height
// capture, tearing down whatever ctx previously held first. Called once at startup and
// again every time the display is actually resized (see on_resize_request).
// Returns 1 on success, 0 on hard failure (out of memory) — MIT-SHM being unavailable is
// not a hard failure, it just means the slower XGetImage fallback path is used.
static int setup_capture_buffers(x11_ctx_t* ctx, int width, int height) {
    teardown_capture_buffers(ctx);
    ctx->width = width;
    ctx->height = height;

    if (XShmQueryExtension(ctx->dpy)) {
        ctx->shm_img = XShmCreateImage(ctx->dpy, DefaultVisual(ctx->dpy, ctx->screen_num),
                                       (unsigned int)DefaultDepth(ctx->dpy, ctx->screen_num),
                                       ZPixmap, NULL, &ctx->shminfo, (unsigned int)width, (unsigned int)height);
        if (ctx->shm_img) {
            ctx->shminfo.shmid = shmget(IPC_PRIVATE, (size_t)ctx->shm_img->bytes_per_line * (size_t)ctx->shm_img->height,
                                        IPC_CREAT | 0600);
            if (ctx->shminfo.shmid >= 0) {
                ctx->shminfo.shmaddr = ctx->shm_img->data = shmat(ctx->shminfo.shmid, 0, 0);
                if (ctx->shminfo.shmaddr != (char*)-1) {
                    ctx->shminfo.readOnly = False;
                    if (XShmAttach(ctx->dpy, &ctx->shminfo)) {
                        ctx->has_shm = 1;
                    } else {
                        shmdt(ctx->shminfo.shmaddr);
                        shmctl(ctx->shminfo.shmid, IPC_RMID, 0);
                        XDestroyImage(ctx->shm_img);
                        ctx->shm_img = NULL;
                    }
                } else {
                    shmctl(ctx->shminfo.shmid, IPC_RMID, 0);
                    XDestroyImage(ctx->shm_img);
                    ctx->shm_img = NULL;
                }
            } else {
                XDestroyImage(ctx->shm_img);
                ctx->shm_img = NULL;
            }
        }
    }

    ctx->fb = malloc((size_t)width * (size_t)height * sizeof(uint32_t));
    return ctx->fb != NULL;
}

#include <time.h>

static unsigned long long get_time_ms(void) {
    struct timespec ts;
    clock_gettime(CLOCK_MONOTONIC, &ts);
    return (unsigned long long)ts.tv_sec * 1000 + ts.tv_nsec / 1000000;
}

// Attempt to switch the X display's first connected output to an existing mode via
// XRandR (the same mechanism `xrandr --output ... --mode WxH` uses). This only selects
// among modes the driver already advertises — it does not synthesize a new modeline.
// An exact req_w x req_h match is preferred; if none exists (very likely when driven by
// an arbitrary window-drag size rather than a fixed admin-chosen resolution), the mode
// with the smallest combined width+height difference is used instead, so live resizing
// still does something reasonable rather than simply failing for any non-standard size.
//
// Assumes a single-output setup (typical for a shared VNC desktop/VM): the screen
// bounding box is grown before the mode switch (required for it to fit) and then shrunk
// to match afterward. On a real multi-monitor host this could clip other outputs, so
// this is intentionally scoped to the common single-display case.
//
// Returns 1 and sets *out_w/*out_h to the resolution actually applied on success; returns
// 0 (leaving *out_w/*out_h untouched) if the output has no usable modes or the switch
// failed.
static int x11_set_resolution(Display* dpy, Window root, int screen_num, int req_w, int req_h, int* out_w, int* out_h) {
    (void)screen_num;
    XRRScreenResources* res = XRRGetScreenResources(dpy, root);
    if (!res) return 0;

    int applied = 0;
    for (int oi = 0; oi < res->noutput && !applied; oi++) {
        XRROutputInfo* out_info = XRRGetOutputInfo(dpy, res, res->outputs[oi]);
        if (!out_info) continue;
        if (out_info->connection != RR_Connected || out_info->crtc == 0) {
            XRRFreeOutputInfo(out_info);
            continue;
        }

        RRMode best_mode = 0;
        int best_w = 0, best_h = 0;
        long best_diff = -1;
        for (int mi = 0; mi < out_info->nmode; mi++) {
            for (int r = 0; r < res->nmode; r++) {
                if (res->modes[r].id != out_info->modes[mi]) continue;
                long diff = labs((long)res->modes[r].width - req_w) + labs((long)res->modes[r].height - req_h);
                if (best_diff < 0 || diff < best_diff) {
                    best_diff = diff;
                    best_mode = res->modes[r].id;
                    best_w = (int)res->modes[r].width;
                    best_h = (int)res->modes[r].height;
                }
                break;
            }
        }
        RRMode found_mode = best_mode;
        if (!found_mode) {
            XRRFreeOutputInfo(out_info);
            continue;
        }

        XRRCrtcInfo* crtc_info = XRRGetCrtcInfo(dpy, res, out_info->crtc);
        if (crtc_info) {
            int min_w, min_h, max_w, max_h;
            XRRGetScreenSizeRange(dpy, root, &min_w, &min_h, &max_w, &max_h);

            // Query live root window attributes directly from the X server
            XWindowAttributes wa;
            XGetWindowAttributes(dpy, root, &wa);
            int cur_w = wa.width;
            int cur_h = wa.height;

            int grown_w = best_w > cur_w ? best_w : cur_w;
            int grown_h = best_h > cur_h ? best_h : cur_h;
            if (grown_w > max_w) grown_w = max_w;
            if (grown_h > max_h) grown_h = max_h;
            if (grown_w != cur_w || grown_h != cur_h) {
                XRRSetScreenSize(dpy, root, grown_w, grown_h, out_info->mm_width, out_info->mm_height);
            }

            Status st = XRRSetCrtcConfig(dpy, res, out_info->crtc, CurrentTime,
                                         crtc_info->x, crtc_info->y, found_mode,
                                         crtc_info->rotation, &res->outputs[oi], 1);
            if (st == Success) {
                // Shrink the bounding box back down to exactly the applied mode
                // (best-effort; harmless no-op if it's already that size).
                XRRSetScreenSize(dpy, root, best_w, best_h, out_info->mm_width, out_info->mm_height);
                XSync(dpy, False);

                // Query the final actual size of the root window to ensure the capture buffers match it exactly
                XGetWindowAttributes(dpy, root, &wa);
                *out_w = wa.width;
                *out_h = wa.height;
                applied = 1;
            }
            XRRFreeCrtcInfo(crtc_info);
        }
        XRRFreeOutputInfo(out_info);
    }

    XRRFreeScreenResources(res);
    return applied;
}

// Set once the display has ever been resized away from its startup resolution (whether
// via the static resize_resolution config option or a live client request), so it can be
// restored on clean shutdown.
static int g_did_resize = 0;

// vnc_server_config_t.on_resize_request: invoked when a client sends SetDesktopSize and
// allow_resize=y. Drives the actual XRandR mode switch and reallocates the capture
// buffers to match — the two things that make this a *live*, not just negotiated, resize.
static int on_resize_request(vnc_server_t* server, vnc_client_t* client,
                             uint16_t req_w, uint16_t req_h,
                             uint16_t* out_w, uint16_t* out_h, void* user_data) {
    (void)client;
    (void)server;
    x11_ctx_t* ctx = (x11_ctx_t*)user_data;

    int applied_w = 0, applied_h = 0;
    if (!x11_set_resolution(ctx->dpy, ctx->root, ctx->screen_num, req_w, req_h, &applied_w, &applied_h)) {
        fprintf(stderr, "Resize request for %ux%u rejected: no usable XRandR mode on any connected output.\n",
                req_w, req_h);
        return VNC_RESIZE_INVALID_LAYOUT;
    }

    if (!setup_capture_buffers(ctx, applied_w, applied_h)) {
        fprintf(stderr, "Resize request for %ux%u: XRandR switch succeeded but capture buffer "
                        "allocation failed.\n", req_w, req_h);
        return VNC_RESIZE_OUT_OF_RESOURCES;
    }

    printf("Live-resized X display to %dx%d (client requested %ux%u).\n", applied_w, applied_h, req_w, req_h);
    g_did_resize = 1;
    *out_w = (uint16_t)applied_w;
    *out_h = (uint16_t)applied_h;
    return VNC_RESIZE_SUCCESS;
}

static volatile sig_atomic_t g_should_exit = 0;
static void handle_exit_signal(int sig) {
    (void)sig;
    g_should_exit = 1;
}

int main(int argc, char* argv[]) {
    int port = 5900;
    char config_password[256] = {0};
    char config_listen_host[64] = {0};
    char config_name[128] = {0};
    int max_clients = 16;
    int websocket_enabled = 0;
    int udp_enabled = 1;
    int resize_w = 0, resize_h = 0; // 0,0 = don't resize; use the display's current resolution
    int allow_resize_enabled = 0;   // let clients live-resize the desktop (default off)
    int audio_enabled = 0;          // stream desktop audio to clients that ask for it (default off)
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
            } else if (strcmp(key, "resize_resolution") == 0) {
                int w = 0, h = 0;
                if (sscanf(value, "%dx%d", &w, &h) == 2 && w > 0 && h > 0) {
                    resize_w = w;
                    resize_h = h;
                } else if (value[0] != '\0') {
                    fprintf(stderr, "Warning: ignoring invalid resize_resolution '%s' (expected WIDTHxHEIGHT)\n", value);
                }
            } else if (strcmp(key, "allow_resize") == 0) {
                if (strcmp(value, "y") == 0 || strcmp(value, "yes") == 0 || strcmp(value, "1") == 0 || strcmp(value, "true") == 0) {
                    allow_resize_enabled = 1;
                } else {
                    allow_resize_enabled = 0;
                }
            } else if (strcmp(key, "enable_audio") == 0) {
                if (strcmp(value, "y") == 0 || strcmp(value, "yes") == 0 || strcmp(value, "1") == 0 || strcmp(value, "true") == 0) {
                    audio_enabled = 1;
                } else {
                    audio_enabled = 0;
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

    // Context for callbacks — zeroed first since setup_capture_buffers()/teardown
    // assume has_shm/fb/shm_img start NULL/0.
    x11_ctx_t ctx;
    memset(&ctx, 0, sizeof(ctx));
    ctx.dpy = dpy;
    ctx.screen_num = DefaultScreen(dpy);
    ctx.root = RootWindow(dpy, ctx.screen_num);
    ctx.last_buttons = 0;
    ctx.selection_win = XCreateSimpleWindow(dpy, ctx.root, 0, 0, 1, 1, 0, 0, 0);

    int orig_width = DisplayWidth(dpy, ctx.screen_num);
    int orig_height = DisplayHeight(dpy, ctx.screen_num);

    if (resize_w > 0 && resize_h > 0 && (resize_w != orig_width || resize_h != orig_height)) {
        int applied_w = 0, applied_h = 0;
        if (x11_set_resolution(dpy, ctx.root, ctx.screen_num, resize_w, resize_h, &applied_w, &applied_h)) {
            printf("Resized X display from %dx%d to %dx%d via XRandR.\n", orig_width, orig_height, applied_w, applied_h);
            g_did_resize = 1;
        } else {
            fprintf(stderr, "Warning: could not switch to %dx%d (no matching XRandR mode found on any connected "
                             "output) — keeping the current resolution.\n", resize_w, resize_h);
        }
    }

    int width = DisplayWidth(dpy, ctx.screen_num);
    int height = DisplayHeight(dpy, ctx.screen_num);

    printf("Sharing X11 screen (resolution %dx%d) on port %d...\n", width, height, port);
    if (password) {
        printf("Authentication enabled (using VncAuth protocol).\n");
    } else {
        printf("Authentication disabled (no password configured).\n");
    }
    printf("Encrypted UDP transport for H.264 video: %s\n", udp_enabled ? "enabled" : "disabled (TCP only)");
    printf("Client-driven live desktop resize: %s\n", allow_resize_enabled ? "enabled" : "disabled");
    printf("Desktop audio streaming (QEMU VNC audio extension): %s\n", audio_enabled ? "enabled" : "disabled");

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
    config.allow_desktop_resize = allow_resize_enabled;
    config.enable_audio = audio_enabled;
    config.on_key = on_key;
    config.on_pointer = on_pointer;
    config.on_resize_request = on_resize_request;
    config.on_clipboard = on_clipboard;
    config.user_data = &ctx;

    vnc_server_t* server = vnc_server_create(&config);
    if (!server) {
        fprintf(stderr, "Error: Failed to create VNC server\n");
        XCloseDisplay(dpy);
        return 1;
    }

    if (!setup_capture_buffers(&ctx, width, height)) {
        fprintf(stderr, "Error: Memory allocation failed for framebuffer\n");
        teardown_capture_buffers(&ctx);
        vnc_server_destroy(server);
        XCloseDisplay(dpy);
        return 1;
    }
    printf(ctx.has_shm ? "MIT-SHM Shared Memory extension enabled successfully.\n"
                       : "MIT-SHM Shared Memory extension not available. Falling back to standard XGetImage (slower).\n");

    int xfixes_event_base = 0;
    int xfixes_error_base = 0;
    int has_xfixes = XFixesQueryExtension(dpy, &xfixes_event_base, &xfixes_error_base);
    if (has_xfixes) {
        Atom clipboard_atom = XInternAtom(dpy, "CLIPBOARD", False);
        XFixesSelectSelectionInput(dpy, ctx.root, clipboard_atom, XFixesSetSelectionOwnerNotifyMask);
    }
    unsigned long last_cursor_serial = 0;

    printf("Server is ready. Connect using a VNC viewer (e.g. 0.0.0.0:%d)\n", port);

    // Caught (rather than left at the default terminate action) so a resized display
    // gets restored to its original resolution below instead of being left resized
    // after the server exits.
    signal(SIGINT, handle_exit_signal);
    signal(SIGTERM, handle_exit_signal);

    unsigned long long next_frame_time = get_time_ms();

    while (!g_should_exit) {
        // Process X11 clipboard/selection events
        while (XPending(dpy)) {
            XEvent ev;
            XNextEvent(dpy, &ev);
            if (ev.type == SelectionRequest) {
                XSelectionRequestEvent* req = &ev.xselectionrequest;
                XEvent resp;
                memset(&resp, 0, sizeof(resp));
                resp.type = SelectionNotify;
                resp.xselection.display = dpy;
                resp.xselection.requestor = req->requestor;
                resp.xselection.selection = req->selection;
                resp.xselection.target = req->target;
                resp.xselection.time = req->time;
                resp.xselection.property = None;

                Atom utf8_atom = XInternAtom(dpy, "UTF8_STRING", False);
                Atom string_atom = XInternAtom(dpy, "STRING", False);
                Atom targets_atom = XInternAtom(dpy, "TARGETS", False);

                if (req->target == targets_atom) {
                    Atom supported[] = { targets_atom, utf8_atom, string_atom };
                    XChangeProperty(dpy, req->requestor, req->property, XA_ATOM, 32,
                                    PropModeReplace, (unsigned char*)supported, 3);
                    resp.xselection.property = req->property;
                } else if ((req->target == utf8_atom || req->target == string_atom) && g_clipboard_text) {
                    XChangeProperty(dpy, req->requestor, req->property, req->target, 8,
                                    PropModeReplace, (unsigned char*)g_clipboard_text, (int)g_clipboard_len);
                    resp.xselection.property = req->property;
                }

                XSendEvent(dpy, req->requestor, True, 0, &resp);
                XFlush(dpy);
            } else if (ev.type == SelectionNotify) {
                XSelectionEvent* sel = &ev.xselection;
                if (sel->property != None) {
                    Atom actual_type;
                    int actual_format;
                    unsigned long nitems, bytes_after;
                    unsigned char* prop_data = NULL;
                    if (XGetWindowProperty(dpy, sel->requestor, sel->property, 0, 65536, True,
                                           AnyPropertyType, &actual_type, &actual_format,
                                           &nitems, &bytes_after, &prop_data) == Success) {
                        if (prop_data && nitems > 0) {
                            if (!g_clipboard_text || g_clipboard_len != nitems ||
                                memcmp(g_clipboard_text, prop_data, nitems) != 0) {
                                free(g_clipboard_text);
                                g_clipboard_text = malloc(nitems + 1);
                                if (g_clipboard_text) {
                                    memcpy(g_clipboard_text, prop_data, nitems);
                                    g_clipboard_text[nitems] = '\0';
                                    g_clipboard_len = nitems;
                                    vnc_server_send_clipboard(server, g_clipboard_text, g_clipboard_len);
                                }
                            }
                        }
                        if (prop_data) XFree(prop_data);
                    }
                }
            } else if (has_xfixes && ev.type == xfixes_event_base + XFixesSelectionNotify) {
                XFixesSelectionNotifyEvent* sev = (XFixesSelectionNotifyEvent*)&ev;
                Atom clipboard_atom = XInternAtom(dpy, "CLIPBOARD", False);
                if (sev->selection == clipboard_atom && sev->owner != ctx.selection_win) {
                    Atom utf8_atom = XInternAtom(dpy, "UTF8_STRING", False);
                    Atom target_prop = XInternAtom(dpy, "VNC_SELECTION", False);
                    XConvertSelection(dpy, clipboard_atom, utf8_atom, target_prop, ctx.selection_win, CurrentTime);
                }
            }
        }

        unsigned long long now = get_time_ms();

        // Target 60 FPS (16 ms frame time)
        if (now >= next_frame_time) {
            // Skip capture entirely when no clients are connected — saves the full
            // XShm read + pixel conversion + tile comparison cost at idle.
            if (vnc_server_has_clients(server)) {
                // Capture screen (ctx.width/height/fb/has_shm/shm_img may have changed
                // since the last iteration if a client requested a live resize)
                if (ctx.has_shm) {
                    XShmGetImage(dpy, ctx.root, ctx.shm_img, 0, 0, AllPlanes);
                    copy_ximage_to_fb(ctx.shm_img, ctx.fb);
                } else {
                    XImage* img = XGetImage(dpy, ctx.root, 0, 0, (unsigned int)ctx.width, (unsigned int)ctx.height, AllPlanes, ZPixmap);
                    if (img) {
                        copy_ximage_to_fb(img, ctx.fb);
                        XDestroyImage(img);
                    }
                }

                // Send screen updates
                vnc_server_update_framebuffer(server, ctx.fb);

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

            next_frame_time += 16;
            if (now > next_frame_time + 16) {
                next_frame_time = now;
            }
        }

        // Poll VNC events with remaining time in the 16ms window
        now = get_time_ms();
        int sleep_time = 0;
        if (next_frame_time > now) {
            sleep_time = (int)(next_frame_time - now);
        }

        vnc_server_poll(server, sleep_time);
    }

    // Cleanup (reached on SIGINT/SIGTERM)
    printf("\nShutting down...\n");
    if (g_did_resize) {
        int restored_w = 0, restored_h = 0;
        if (x11_set_resolution(dpy, ctx.root, ctx.screen_num, orig_width, orig_height, &restored_w, &restored_h)) {
            printf("Restored X display to %dx%d.\n", restored_w, restored_h);
        } else {
            fprintf(stderr, "Warning: could not restore the original %dx%d resolution.\n", orig_width, orig_height);
        }
    }
    teardown_capture_buffers(&ctx);
    vnc_server_destroy(server);
    XCloseDisplay(dpy);
    return 0;
}
